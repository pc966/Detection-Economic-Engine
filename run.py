from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv('PORT', 5100))
    debug = os.getenv('DEBUG', 'False') == 'True'
    app.run(host="0.0.0.0", port=port, debug=debug)