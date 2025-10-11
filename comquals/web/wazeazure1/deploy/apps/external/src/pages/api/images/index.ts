import path from 'node:path';

const uploadConfig = {
  maxSize: 10 * 1024 * 1024, // 10MB
  allowedTypes: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'],
  allowedExtensions: ['png', 'jpg', 'jpeg', 'gif', 'webp'],
};

//TODO Implement pagination and filtering in UI/UX
export async function GET() {
  const url = `http://localhost:5000/api/images`;
  const resp = await fetch(url, { method: 'GET' });
  return new Response(resp.body, { status: resp.status });
}

export async function POST({ request }: { request: Request }) {
  const url = `http://localhost:5000/api/images`;

  const formData = await request.formData();
  const file = formData.get('file') as File | null;
  const title = formData.get('title') as string | null;

  if (!file) {
    return new Response(
      JSON.stringify({ ok: false, error: 'No file uploaded' }),
      { status: 400 },
    );
  }

  if (!uploadConfig.allowedTypes.includes(file.type)) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Invalid file type' }),
      { status: 400 },
    );
  }
  if (file.size > uploadConfig.maxSize) {
    return new Response(
      JSON.stringify({ ok: false, error: 'File too large' }),
      { status: 400 },
    );
  }

  const ext = path.extname(file.name).replace('.', '').toLowerCase();
  if (!uploadConfig.allowedExtensions.includes(ext)) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Invalid file extension' }),
      { status: 400 },
    );
  }

  const fd = new FormData();
  fd.append('file', file, file.name);
  if (title) fd.append('title', title);

  const resp = await fetch(url, {
    method: 'POST',
    body: fd,
  });
  return new Response(resp.body, { status: resp.status });
}
