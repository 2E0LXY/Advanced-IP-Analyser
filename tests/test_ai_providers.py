import io
import json
import unittest

from ip_analyser.ai_providers import AIProviderError, generate_text, list_models


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class _Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return _Response(json.dumps(next(self.responses)).encode("utf-8"))


class ProviderModelTests(unittest.TestCase):
    def test_openai_uses_official_endpoint_and_filters_non_text_models(self):
        opener = _Opener([{"data": [{"id": "gpt-text"}, {"id": "text-embedding-3-small"}]}])
        models = list_models("OpenAI", "provider-secret", opener=opener)
        request, _timeout = opener.requests[0]
        self.assertEqual(request.full_url, "https://api.openai.com/v1/models")
        self.assertEqual(request.get_header("Authorization"), "Bearer provider-secret")
        self.assertNotIn("provider-secret", request.full_url)
        self.assertEqual([item.identifier for item in models], ["gpt-text"])

    def test_openrouter_uses_bearer_and_text_modality(self):
        opener = _Opener([{"data": [
            {"id": "vendor/text", "name": "Text", "architecture": {"output_modalities": ["text"]}},
            {"id": "vendor/image", "name": "Image", "architecture": {"output_modalities": ["image"]}},
        ]}])
        models = list_models("OpenRouter", "provider-secret", opener=opener)
        request, _timeout = opener.requests[0]
        self.assertEqual(request.full_url, "https://openrouter.ai/api/v1/models")
        self.assertEqual(request.get_header("Authorization"), "Bearer provider-secret")
        self.assertEqual([item.identifier for item in models], ["vendor/text"])

    def test_gemini_paginates_and_only_returns_generate_content_models(self):
        opener = _Opener([
            {"models": [{"name": "models/gemini-a", "displayName": "A",
                         "supportedGenerationMethods": ["generateContent"]}], "nextPageToken": "next"},
            {"models": [{"name": "models/embed-a", "supportedGenerationMethods": ["embedContent"]},
                        {"name": "models/gemini-b", "displayName": "B",
                         "supportedGenerationMethods": ["generateContent"]}]},
        ])
        models = list_models("Gemini", "provider-secret", opener=opener)
        self.assertEqual([item.identifier for item in models], ["gemini-a", "gemini-b"])
        for request, _timeout in opener.requests:
            self.assertEqual(request.get_header("X-goog-api-key"), "provider-secret")
            self.assertNotIn("provider-secret", request.full_url)
        self.assertIn("pageToken=next", opener.requests[1][0].full_url)

    def test_generation_payloads_are_provider_native_and_stateless(self):
        openai = _Opener([{"output_text": "OpenAI result"}])
        self.assertEqual(generate_text("OpenAI", "gpt-text", "provider-secret", "system", "prompt",
                                       opener=openai), "OpenAI result")
        request = openai.requests[0][0]
        self.assertEqual(request.full_url, "https://api.openai.com/v1/responses")
        self.assertFalse(json.loads(request.data)["store"])

        router = _Opener([{"choices": [{"message": {"content": "Router result"}}]}])
        self.assertEqual(generate_text("OpenRouter", "vendor/text", "provider-secret", "system", "prompt",
                                       opener=router), "Router result")
        self.assertTrue(router.requests[0][0].full_url.endswith("/chat/completions"))

        gemini = _Opener([{"candidates": [{"content": {"parts": [{"text": "Gemini result"}]}}]}])
        self.assertEqual(generate_text("Gemini", "gemini-a", "provider-secret", "system", "prompt",
                                       opener=gemini), "Gemini result")
        self.assertTrue(gemini.requests[0][0].full_url.endswith("/models/gemini-a:generateContent"))

    def test_rejects_empty_or_malformed_model_responses(self):
        with self.assertRaises(AIProviderError):
            list_models("OpenAI", "provider-secret", opener=_Opener([{"data": "bad"}]))
        with self.assertRaises(AIProviderError):
            generate_text("Gemini", "gemini-a", "provider-secret", "system", "prompt",
                          opener=_Opener([{"candidates": []}]))


if __name__ == "__main__":
    unittest.main()
