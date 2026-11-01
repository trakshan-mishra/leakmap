import gradio as gr
from gradio_client import Client

demo = gr.Interface(fn=lambda s: s.upper(), inputs="text", outputs="text")
demo.launch(prevent_thread_lock=True, share=False)
print(Client(demo.local_url).predict("Rahul Kumar rahul.k@example.com", api_name="/predict"))
demo.close()
