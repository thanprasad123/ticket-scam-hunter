from google import genai

from analyze import MODEL, VERTEX_LOCATION, VERTEX_PROJECT


def main() -> int:
    client = genai.Client(
        vertexai=True,
        project=VERTEX_PROJECT,
        location=VERTEX_LOCATION,
    )

    response = client.models.generate_content(
        model=MODEL,
        contents=(
            "Is this URL suspicious? https://cheapworldcuptickets2026.com "
            "- answer in one sentence."
        ),
    )

    print(response.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
