from fastapi import FastAPI, Query, Body
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn
import time

from checker_script import check_card  # তোমার মূল স্ক্রিপ্ট ফাইল

app = FastAPI()

# Static ফাইল (HTML/JS) সার্ভ করার জন্য
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    from fastapi.responses import FileResponse
    return FileResponse('static/index.html')

@app.get("/check")
def check_single_card(card: str = Query(..., description="Format: CC|MM|YY|CVV")):
    result = check_card(card)
    return JSONResponse(content=result)

@app.post("/bulk-check")
def check_multiple_cards(cards: list[str] = Body(..., embed=True)):
    results = []
    for card in cards:
        result = check_card(card)
        results.append(result)
        time.sleep(0)  # ✅ 2-second delay per card
    return JSONResponse(content={"results": results})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)
