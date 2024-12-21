from flask import Flask , render_template , request , jsonify

app = Flask(__name__)

@app.route('/',methods=['GET'])
def home():
    return render_template('docs.html')

@app.route('/check_health',methods=['GET'])
def check_health():
    client_ip = request.remote_addr
    response_data = {
        "status": "Server is running OK",
        "client_ip": client_ip
    }
    return jsonify(response_data), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
