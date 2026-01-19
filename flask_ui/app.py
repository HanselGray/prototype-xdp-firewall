from flask import Flask, request, jsonify, send_from_directory
import requests

FIREWALL_API = "http://127.0.0.1:8080"
TIMEOUT = 3  # seconds

app = Flask(__name__)


def call_firewall_api(method, path, json=None):
    url = f"{FIREWALL_API}{path}"

    try:
        r = requests.request(
            method,
            url,
            json=json,
            timeout=TIMEOUT
        )

        r.raise_for_status()  # raises for 4xx / 5xx

        try:
            return r.json(), r.status_code
        except ValueError:
            return {
                "error": "Invalid JSON from firewall API"
            }, 502

    except requests.exceptions.Timeout:
        return {
            "error": "Firewall API timeout"
        }, 504

    except requests.exceptions.ConnectionError:
        return {
            "error": "Firewall API unreachable"
        }, 503

    except requests.exceptions.HTTPError as e:
        # Try to forward upstream error if possible
        try:
            return r.json(), r.status_code
        except Exception:
            return {
                "error": "Firewall API error",
                "status": r.status_code
            }, r.status_code

    except Exception as e:
        return {
            "error": "Unexpected error",
            "details": str(e)
        }, 500



@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/rules", methods=["GET"])
def list_rules():
    data, status = call_firewall_api("GET", "/rules")
    return jsonify(data), status


@app.route("/rules", methods=["POST"])
def add_rule():
    try:
        r = requests.post(
            f"{FIREWALL_API}/rules",
            json=request.json,
            timeout=2
        )

        if r.status_code == 201:
            return jsonify({"status": "ok"}), 201

        return jsonify({
            "error": "Firewall rejected rule",
            "status_code": r.status_code,
            "body": r.text
        }), r.status_code

    except requests.RequestException:
        return jsonify({"error": "Firewall API unreachable"}), 503


@app.route("/rules", methods=["DELETE"])
def delete_rule():
    try:
        r = requests.delete(
            f"{FIREWALL_API}/rules",
            json=request.json,
            timeout=2
        )

        if r.status_code == 200:
            return jsonify({"status": "ok"}), 200

        return jsonify({
            "error": "Firewall failed to delete rule",
            "status_code": r.status_code,
            "body": r.text
        }), r.status_code

    except requests.RequestException:
        return jsonify({"error": "Firewall API unreachable"}), 503


@app.route("/health")
def health():
    data, status = call_firewall_api("GET", "/health")
    return jsonify(data), status

@app.route("/default", methods=["GET", "POST"])
def default_action():
    try:
        if request.method == "GET":
            r = requests.get(f"{FIREWALL_API}/default", timeout=2)
        else:
            r = requests.post(
                f"{FIREWALL_API}/default",
                json=request.json,
                timeout=2
            )

        return jsonify(r.json()), r.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "error",
            "message": "Firewall API unreachable"
        }), 503

    except requests.exceptions.Timeout:
        return jsonify({
            "status": "error",
            "message": "Firewall API timeout"
        }), 504

    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid response from Firewall API"
        }), 502

if __name__ == "__main__":
    print("[+] Firewall UI (Flask) starting...")
    print(f"[+] Forwarding requests to: {FIREWALL_API}")
    app.run(host="0.0.0.0", port=8000, debug=False)

