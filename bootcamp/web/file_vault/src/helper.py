import os
import time
import threading

UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 4 * 1024 * 1024  #4 MB max file size
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'rtf',  # Text/Document files
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'  # Image files
}

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_path(filepath):
    blacklist = [
        '/../', '../', '/..', '/.', './'
    ]
    for b in blacklist:
        filepath = filepath.replace(b, "")
    
    return filepath

def get_file_icon(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    image_exts = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'}
    doc_exts = {'pdf', 'doc', 'docx', 'rtf'}
    
    if ext in image_exts:
        return 'file-image'
    elif ext in doc_exts:
        return 'file-text'
    elif ext == 'txt':
        return 'file-lines'
    else:
        return 'file'

def format_file_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def cleanup_uploads():
    UPLOAD_FOLDER = 'uploads'
    CLEANUP_INTERVAL = 10 * 60  # 10 minutes
    
    while True:
        try:
            if os.path.exists(UPLOAD_FOLDER):
                for root, dirs, files in os.walk(UPLOAD_FOLDER):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            os.remove(file_path)
                        except:
                            pass
            time.sleep(CLEANUP_INTERVAL)
        except:
            time.sleep(300)  # Wait 5 minutes on error

def start_cleanup_thread():
    thread = threading.Thread(target=cleanup_uploads, daemon=True)
    thread.start()