import re
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Chat (Responses API + Vector Store + Plotly)", page_icon="💬", layout="centered")

# --- Secrets / Config ---
API_KEY = st.secrets.get("OPENAI_API_KEY")
MODEL = st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")
VECTOR_STORE_ID = st.secrets.get("OPENAI_VECTOR_STORE_ID", "")

if not API_KEY:
    st.error("Missing OPENAI_API_KEY in .streamlit/secrets.toml")
    st.stop()

if not VECTOR_STORE_ID:
    st.error("Missing OPENAI_VECTOR_STORE_ID in .streamlit/secrets.toml (required for file_search).")
    st.stop()

client = OpenAI(api_key=API_KEY)

st.title("Get Better at Flatter Chatbot")

# --- Chat history in session state ---
# Entries can be:
#   {"role": "user"|"assistant", "content": "text"}  OR
#   {"role": "assistant", "plot": <plotly_figure>, "caption": "..."}
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Utilities ---
def build_transcript(history):
    """Compile chat history into a single text transcript for Responses 'input'."""
    lines = []
    for m in history:
        if "plot" in m:
            lines.append("Assistant: [chart]")
        else:
            speaker = "User" if m["role"] == "user" else "Assistant"
            lines.append(f"{speaker}: {m['content']}")
    return "\n".join(lines)

def extract_python_code(text: str):
    """
    Extract a Python code block wrapped as:
    ```python
    <code>
    ```
    Returns the inner code or None.
    """
    pattern = r"```python\s(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    return matches[0] if matches else None

def remove_python_blocks(text: str):
    """Remove all ```python ...``` fenced code blocks from the text."""
    return re.sub(r"```python\s.*?```", "", text, flags=re.DOTALL).strip()

# --- Render previous turns (including persistent plots) ---
for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        if "plot" in m:
            st.plotly_chart(m["plot"], theme="streamlit", use_container_width=True)
            if m.get("caption"):
                st.caption(m["caption"])
        else:
            st.markdown(m["content"])

# --- Input box ---
user_input = st.chat_input("Type your question… (e.g., “visualize…”, “plot…”, “show a chart of…”)")

if user_input:
    # Show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    transcript = build_transcript(st.session_state.messages)

    # --- Instructions ---
    # 1) Answer ONLY from KB (file_search). 2) Page markers -> formatted citation.
    # 3) If the user asks for a chart/plot/graph/visualization, return Plotly-only Python code in ```python fences,
    #    with a figure variable named `fig` and WITHOUT fig.show(). You may include a short natural-language explanation
    #    BEFORE the code block, but do not include any other code outside the fenced block.
    base_instructions = (
        "You are a careful, concise assistant providing individual information on Prof. Markus Reitzig's Book 'Get Better at Flatter'. "
        "Use ONLY the information retrieved from the file_search tool. "
        "If a retrieved chunk contains a page marker like '{:.page-1}', translate it into a citation in the following format:\n\n"
        "Reitzig, M. (2022). Get better at flatter. Springer International Publishing., p. <page number>\n\n"
        "Example: If the marker is '{:.page-3}', cite it as 'Reitzig, M. (2022). Get better at flatter. Springer International Publishing., p. 3'. "
        "If no page marker is present, omit the page reference. "
        "If the knowledge base does not contain the answer, reply with: "
        "\"I don't know based on the provided knowledge base.\" "
        "Do not rely on outside or general knowledge. Do not fabricate facts."
    )

    plotting_guidance = (
        "If the user asks to visualize, chart, graph, plot, or show a figure, produce Plotly-only Python code. "
        "Return the code wrapped in a single fenced block exactly like:\n"
        "```python\n"
        "# (imports if needed)\n"
        "# construct data from the retrieved context\n"
        "# create a Plotly figure assigned to the variable `fig`\n"
        "```\n"
        "Requirements:\n"
        "- Use Plotly only (no matplotlib).\n"
        "- Name the resulting figure variable `fig`.\n"
        "- Do NOT call fig.show().\n"
        "- You may include a brief natural-language explanation before the code block."
    )

    instructions = f"{base_instructions}\n\n{plotting_guidance}"

    req = {
        "model": MODEL,
        "input": transcript,
        "instructions": instructions,
        "tools": [{
            "type": "file_search",
            "vector_store_ids": [VECTOR_STORE_ID],
        }],
    }

    # Call the API
    try:
        resp = client.responses.create(**req)
        assistant_text = resp.output_text or ""
    except Exception as e:
        assistant_text = f"Sorry, there was an error calling the API:\n\n```\n{e}\n```"
        resp = None

    # Assistant bubble
    with st.chat_message("assistant"):
        # Try to find a plot code block (the LLM decides if one is needed)
        code = extract_python_code(assistant_text)
        if code:
            # 1) Show any explanatory text (minus code)
            explanation = remove_python_blocks(assistant_text)
            if explanation:
                st.markdown(explanation)

            # 2) Exec the code (hide the code itself). Expect a variable `fig`.
            try:
                # Strip any fig.show() just in case
                safe_code = code.replace("fig.show()", "").strip()
                exec_globals = {"st": st}
                exec_locals = {}
                exec(safe_code, exec_globals, exec_locals)

                # Retrieve the figure
                fig = None
                if "fig" in exec_locals:
                    fig = exec_locals["fig"]
                elif "fig" in exec_globals:
                    fig = exec_globals["fig"]

                if fig is not None and hasattr(fig, "to_dict"):
                    st.plotly_chart(fig, theme="streamlit", use_container_width=True)
                    # Persist the plot in history so it stays visible
                    st.session_state.messages.append({
                        "role": "assistant",
                        "plot": fig,
                        "caption": None  # optional caption string
                    })
                else:
                    st.info("I generated code but couldn't detect a Plotly figure named 'fig'.")
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": "Chart generation attempted, but no figure was detected."
                    })
            except Exception as ex:
                st.error(f"Plot execution error:\n{ex}")
                st.session_state.messages.append({"role": "assistant", "content": f"Plot execution error: {ex}"})
        else:
            # No code -> regular text answer
            st.markdown(assistant_text)
            st.session_state.messages.append({"role": "assistant", "content": assistant_text})
