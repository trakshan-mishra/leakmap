import os
os.environ.setdefault("OPENAI_API_KEY", "sk-test-not-a-real-key")
from crewai import Agent, Crew, Task

agent = Agent(role="Support agent", goal="Resolve the customer's KYC issue",
              backstory="You work at a fintech in Bengaluru.", llm="gpt-4o-mini", verbose=False)
task = Task(description="Customer Rahul Kumar (rahul.k@example.com, +91 98765 43210, Aadhaar 2000 0000 0009, "
                        "PAN ABCPK1234F) says his KYC failed. Draft a reply.",
            expected_output="A short reply", agent=agent)
try:
    Crew(agents=[agent], tasks=[task]).kickoff()
except Exception as e:  # stub mode answers {}, so the LLM call is expected to fail
    print("crew ended:", type(e).__name__, str(e)[:200])
