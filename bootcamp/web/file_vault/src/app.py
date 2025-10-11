from flask import Flask, request, jsonify, send_file, render_template, Response
import os
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import mimetypes
from datetime import datetime
import helper

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = helper.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = helper.MAX_FILE_SIZE

os.makedirs(helper.UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/files-page')
def files_page():
    try:
        files = []
        for root, dirs, filenames in os.walk(app.config['UPLOAD_FOLDER']):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, app.config['UPLOAD_FOLDER'])
                stat = os.stat(full_path)
                
                files.append({
                    'filename': filename,
                    'path': rel_path.replace('\\', '/'),
                    'size': helper.format_file_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'icon': helper.get_file_icon(filename),
                    'download_url': f'/files/{rel_path.replace(os.sep, "/")}'
                })
        
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        return render_template('files.html', files=files)
        
    except Exception as e:
        return render_template('files.html', files=[], error=str(e))

@app.route('/upload', methods=['POST'])
def upload_files():
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        
        if not files or all(file.filename == '' for file in files):
            return jsonify({'error': 'No files selected'}), 400
        
        uploaded_files = []
        errors = []
        
        for file in files:
            if file and file.filename:
                if not helper.allowed_file(file.filename):
                    errors.append(f'{file.filename}: File type not allowed')
                    continue
                
                # Makesure no Path Traversal possible
                filename = secure_filename(file.filename)
                
                counter = 1
                original_filename = filename
                while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
                    name, ext = os.path.splitext(original_filename)
                    filename = f"{name}_{counter}{ext}"
                    counter += 1
                
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                uploaded_files.append({
                    'original_name': file.filename,
                    'saved_as': filename,
                    'size': os.path.getsize(filepath)
                })
        
        result = {'uploaded_files': uploaded_files}
        if errors:
            result['errors'] = errors
        
        return jsonify(result), 200
        
    except RequestEntityTooLarge:
        return jsonify({'error': 'File too large. Maximum size is 4MB'}), 413
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/files/<path:filepath>')
def download_file(filepath):
    try:
        filepath = helper.sanitize_path(filepath)
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], filepath)
        
        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            return jsonify({'error': 'File not found'}), 404
        
        mimetype = mimetypes.guess_type(full_path)[0] or 'text/plain'
        
        with open(full_path, 'rb') as f:
            content = f.read()

        response = Response(content, mimetype=mimetype)
        response.headers['Content-Disposition'] = f'inline; filename="{os.path.basename(full_path)}"'
        response.headers['Content-Length'] = str(os.path.getsize(full_path))
        return response
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/files')
def list_files():
    try:
        files = []
        for root, dirs, filenames in os.walk(app.config['UPLOAD_FOLDER']):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, app.config['UPLOAD_FOLDER'])
                
                files.append({
                    'filename': filename,
                    'path': rel_path.replace('\\', '/'),  # Use forward slashes for URLs
                    'size': os.path.getsize(full_path),
                    'download_url': f'/files/{rel_path.replace(os.sep, "/")}'
                })
        
        return jsonify({'files': files}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large. Maximum size is 4MB'}), 413

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

if __name__ == '__main__':
    print("Server running at: http://localhost:6969")
    app.run(host='0.0.0.0', port=6969)
    helper.start_cleanup_thread()