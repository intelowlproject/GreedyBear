from greedybear.models import GeneralHoneypot
from tests import CustomTestCase


class GeneralHoneypotViewTestCase(CustomTestCase):
    def test_200_all_general_honeypots(self):
        initial_count = GeneralHoneypot.objects.count()
        # add a general honeypot not active
        GeneralHoneypot(name="Adbhoney", active=False).save()
        self.assertEqual(GeneralHoneypot.objects.count(), initial_count + 1)

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
