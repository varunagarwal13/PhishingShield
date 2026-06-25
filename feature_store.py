import json


class DomainFeatureStore:
    def __init__(self, cache=None, ttl_seconds=21600):
        self.cache = cache
        self.ttl_seconds = ttl_seconds

    def _key(self, domain):
        return f"phish8:features:{domain}"

    def get(self, domain):
        if not self.cache:
            return None
        try:
            cached = self.cache.get(self._key(domain))
            if not cached:
                return None
            value = json.loads(cached)
            value["feature_store_hit"] = True
            return value
        except Exception as e:
            print(f"Feature store read error for {domain}: {e}")
            return None

    def set(self, domain, features):
        if not self.cache:
            return
        try:
            value = dict(features)
            value["feature_store_hit"] = False
            self.cache.set(self._key(domain), json.dumps(value), ex=self.ttl_seconds)
        except Exception as e:
            print(f"Feature store write error for {domain}: {e}")

    async def get_or_compute(self, domain, compute_fn):
        cached = self.get(domain)
        if cached is not None:
            return cached
        features = await compute_fn(domain)
        result = dict(features)
        result["feature_store_hit"] = False
        self.set(domain, result)
        return result
