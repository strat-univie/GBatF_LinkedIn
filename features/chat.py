# streamlit_app/features/chat.py
import streamlit as st
from core.utils import build_transcript, extract_python_code, remove_python_blocks

def render_chat(client, model: str, vector_store_id: str):
    # history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # render previous turns
    for m in st.session_state.messages:
        with st.chat_message(m["role"]):
            if "plot" in m:
                st.plotly_chart(m["plot"], theme="streamlit", use_container_width=True)
                if m.get("caption"): st.caption(m["caption"])
            else:
                st.markdown(m["content"])

    # input
    user_input = st.chat_input("Type your question… (e.g., “visualize…”, “plot…”, “show a chart of…”)")
    if not user_input:
        return

    # show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"): st.markdown(user_input)

    transcript = build_transcript(st.session_state.messages)

    base_instructions = (
        "You are a careful, concise assistant providing individual information on Prof. Markus Reitzig's Book 'Get Better at Flatter'. "
        "Use ONLY the information retrieved from the file_search tool. "
        "If a retrieved chunk contains a page marker like '{:.page-1}', translate it into a citation in the following format:\n\n"
        "Reitzig, M. (2022). Get better at flatter. Springer International Publishing., p. <page number>\n\n"
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
        "model": model,
        "input": transcript,
        "instructions": instructions,
        "tools": [{"type": "file_search", "vector_store_ids": [vector_store_id]}],
    }

    try:
        resp = client.responses.create(**req)
        assistant_text = resp.output_text or ""
    except Exception as e:
        assistant_text = f"Sorry, there was an error calling the API:\n\n```\n{e}\n```"
        resp = None

    with st.chat_message("assistant"):
        code = extract_python_code(assistant_text)
        if code:
            explanation = remove_python_blocks(assistant_text)
            if explanation: st.markdown(explanation)
            try:
                safe_code = code.replace("fig.show()", "").strip()
                exec_globals = {"st": st}
                exec_locals = {}
                exec(safe_code, exec_globals, exec_locals)
                fig = exec_locals.get("fig") or exec_globals.get("fig")
                if fig is not None and hasattr(fig, "to_dict"):
                    st.plotly_chart(fig, theme="streamlit", use_container_width=True)
                    st.session_state.messages.append({"role": "assistant", "plot": fig, "caption": None})
                else:
                    st.info("I generated code but couldn't detect a Plotly figure named 'fig'.")
                    st.session_state.messages.append({"role": "assistant", "content": "Chart generation attempted, but no figure was detected."})
            except Exception as ex:
                st.error(f"Plot execution error:\n{ex}")
                st.session_state.messages.append({"role": "assistant", "content": f"Plot execution error: {ex}"})
        else:
            st.markdown(assistant_text)
            st.session_state.messages.append({"role": "assistant", "content": assistant_text})
