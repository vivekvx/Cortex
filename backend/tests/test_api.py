import unittest

from fastapi.middleware.cors import CORSMiddleware

from cortex_shield.api import create_app
from cortex_shield.trace_store import TraceStore


class ApiTests(unittest.TestCase):
    def test_app_enables_local_dashboard_cors(self):
        app = create_app(store=TraceStore(":memory:"))

        middleware_classes = [entry.cls for entry in app.user_middleware]

        self.assertIn(CORSMiddleware, middleware_classes)


if __name__ == "__main__":
    unittest.main()
