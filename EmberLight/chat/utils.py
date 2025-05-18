import google.generativeai as genai
from django.conf import settings

genai.configure(api_key=settings.GEMINI_API_KEY)

SYSTEM_PROMPT = """
Eres un asistente de salud mental en español. Sigue estas reglas:

1. **Contexto del Diario**:
   - Usa las entradas del diario para respuestas personalizadas
   - Destaca patrones emocionales ("Veo que has tenido días [emoción] cuando...")

2. **Reflexión Emocional**:
   - Nombra la emoción ("Parece que te sientes [emoción]")
   - Valida la experiencia ("Es comprensible sentirse así cuando...")

3. **Formato**:
   - 3-4 oraciones máximo
   - Termina con pregunta abierta
   - Usa **negritas** para secciones (pero no muestres los asteriscos)

4. **Memoria**:
   - Recuerda la conversación anterior
   - Mantén coherencia con lo discutido

Ejemplo:
"Veo en tu diario que mencionaste [x]. Parece que te sientes [emoción], lo cual es comprensible porque [razón]. ¿Cómo ha evolucionado esto para ti?"
"""

"""
You are a mental health assistant. The user has shared some journal entries with you.
Use this context to provide personalized advice. Be empathetic and supportive.
Generate between 3-4 sentences for each answer.
Use emotional reflection: name the emotion you detect, validate the user's
experience. Gently mirror their concern back and highlight patterns you've noticed.
Ask open ended questions to deepen understanding.
Generate your answers in Spanish.
"""

def get_chat_model():
    return genai.GenerativeModel(
        "gemini-2.0-flash-lite",
        system_instruction=SYSTEM_PROMPT,
        generation_config=genai.types.GenerationConfig(
            temperature=0.7,
            top_p=0.9,
            top_k=40,
        )
    )

"""
def generate_ai_response(prompt):
    model = genai.GenerativeModel("gemini-2.0-flash-lite", 
        system_instruction=SYSTEM_PROMPT,
        generation_config=genai.types.GenerationConfig(
            temperature=0.7,  # Balanced creativity
            top_p=0.9,       # This is for better quality responses
            top_k=40         # This is for thoughtful word choices
        ))
    return model.generate_content(prompt).text.strip()
"""