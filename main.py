"""
Entry point: uvicorn trustable_memory.api:app --reload
or: python main.py
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "trustable_memory.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
