import json
import unittest
from unittest.mock import MagicMock, patch

from ip_analyser.home_assistant import (
    call_service,
    list_entities,
    set_entity_brightness,
    set_entity_power,
    validate_local_url,
)

TOKEN = "local-long-lived-token-value"
LOCAL_INFO = [(2, 1, 6, "", ("192.168.1.10", 0))]


def _response(payload):
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    response.__exit__.return_value = False
    return response


class HomeAssistantTests(unittest.TestCase):
    @patch("ip_analyser.home_assistant.socket.getaddrinfo", return_value=LOCAL_INFO)
    def test_local_url_is_normalized(self, _resolve):
        self.assertEqual(
            validate_local_url("http://homeassistant.local:8123/"),
            "http://homeassistant.local:8123")

    @patch("ip_analyser.home_assistant.socket.getaddrinfo",
           return_value=[(2, 1, 6, "", ("8.8.8.8", 0))])
    def test_public_controller_is_rejected_before_token_use(self, _resolve):
        with self.assertRaisesRegex(ValueError, "public host"):
            validate_local_url("https://example.com")

    @patch("ip_analyser.home_assistant._open_local")
    @patch("ip_analyser.home_assistant.socket.getaddrinfo", return_value=LOCAL_INFO)
    def test_lists_all_supported_control_domains(self, _resolve, open_local):
        open_local.return_value = _response([
            {"entity_id": "light.desk", "state": "on", "attributes": {
                "friendly_name": "Desk light", "brightness": 128}},
            {"entity_id": "lock.front_door", "state": "locked", "attributes": {
                "friendly_name": "Front door"}},
            {"entity_id": "sensor.temperature", "state": "20", "attributes": {}},
        ])

        entities = list_entities("http://homeassistant.local:8123", TOKEN)

        self.assertEqual([item.entity_id for item in entities], ["light.desk", "lock.front_door"])
        light = entities[0]
        self.assertEqual(light.brightness, 50)
        self.assertTrue(light.can_brightness)
        self.assertEqual(light.provider, "Home Assistant")

    @patch("ip_analyser.home_assistant._open_local")
    @patch("ip_analyser.home_assistant.socket.getaddrinfo", return_value=LOCAL_INFO)
    def test_generic_action_targets_selected_entity(self, _resolve, open_local):
        open_local.side_effect = [_response([]), _response([])]

        call_service(
            "http://homeassistant.local:8123", TOKEN, "media_player.volume_set",
            "media_player.lounge", {"volume_level": 0.25})

        request = open_local.call_args_list[0].args[0]
        self.assertTrue(request.full_url.endswith("/api/services/media_player/volume_set"))
        self.assertEqual(json.loads(request.data), {
            "volume_level": 0.25, "entity_id": "media_player.lounge"})
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")

    @patch("ip_analyser.home_assistant.call_service", return_value=[])
    def test_domain_specific_power_actions(self, call):
        set_entity_power("http://local", TOKEN, "lock.front_door", True)
        set_entity_power("http://local", TOKEN, "cover.garage", False)

        self.assertEqual(call.call_args_list[0].args[2], "lock.unlock")
        self.assertEqual(call.call_args_list[1].args[2], "cover.close_cover")

    @patch("ip_analyser.home_assistant.call_service", return_value=[])
    def test_brightness_uses_percentage(self, call):
        set_entity_brightness("http://local", TOKEN, "light.desk", 35)

        self.assertEqual(call.call_args.args[2:4], ("light.turn_on", "light.desk"))
        self.assertEqual(call.call_args.args[4], {"brightness_pct": 35})


if __name__ == "__main__":
    unittest.main()
