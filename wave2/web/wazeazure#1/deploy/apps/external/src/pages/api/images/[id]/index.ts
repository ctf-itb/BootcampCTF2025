export async function GET({ params }: { params: { id: string } }) {
  if (!params?.id || typeof params.id !== 'string' || isNaN(Number(params.id)))
    return new Response(
      JSON.stringify({ ok: false, error: 'Invalid or missing id parameter' }),
      { status: 400 },
    );
  const id = params.id;
  const url = `http://localhost:5000/api/images/${encodeURIComponent(id)}`;
  const resp = await fetch(url, { method: 'GET' });
  return new Response(resp.body, { status: resp.status });
}
