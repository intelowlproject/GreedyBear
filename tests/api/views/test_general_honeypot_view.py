from greedybear.models import Honeypot
from tests import CustomTestCase


class HoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        initial_count = Honeypot.objects.count()
        # add a general honeypot not active
        Honeypot(name="Adbhoney", active=False).save()
        self.assertEqual(Honeypot.objects.count(), initial_count + 1)

        response = self.client.get("/api/general_honeypot")
        self.assertEqual(response.status_code, 200)
        # Verify the newly created honeypot is in the response
        self.assertIn("Adbhoney", response.json())

    def test_200_active_general_honeypots(self):
        response = self.client.get("/api/general_honeypot?onlyActive=true")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        # Should include active honeypots from CustomTestCase
        self.assertIn("Heralding", result)
        self.assertIn("Ciscoasa", result)
        # Should NOT include inactive honeypot
        self.assertNotIn("Ddospot", result)
