from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('sql_attempts.log')
    ]
)
logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    logger.warning(f"Login attempt - Username: {username}")

    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    logger.info(f"Request details - IP: {client_ip}, User-Agent: {user_agent}")

    return jsonify({
        'status': 'error',
        'message': 'Invalid login attempt',
        'details': {
            'username': username,
            'ip': client_ip
        }
    }), 401

@app.route('/status')
def status():
    return jsonify({
        'status': 'running',
        'message': 'Test server is running'
    })

if __name__ == '__main__':
    logger.info("Starting test server...")
    app.run(host='127.0.0.1', port=5001, debug=True)