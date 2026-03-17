import { NextResponse, NextRequest } from "next/server";
import { cookies } from 'next/headers'
import { sunoApi } from "@/lib/SunoApi";
import { corsHeaders } from "@/lib/utils";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  if (req.method === 'POST') {
    try {
      const body = await req.json();
      const { clip_id } = body;
      if (!clip_id) {
        return new NextResponse(JSON.stringify({ error: 'Clip id is required' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }
      const audioInfo = await (await sunoApi((await cookies()).toString())).concatenate(clip_id);
      return new NextResponse(JSON.stringify(audioInfo), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    } catch (error: any) {
      const errorMessage = error.response?.data?.detail || error.message || 'Unknown error';
      const errorStatus = error.response?.status || 500;

      console.error('Error generating concatenating audio:', errorMessage);

      if (errorStatus === 402) {
        return new NextResponse(JSON.stringify({ error: errorMessage }), {
          status: 402,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }
      return new NextResponse(JSON.stringify({ error: 'Internal server error: ' + errorMessage }), {
        status: errorStatus,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  } else {
    return new NextResponse('Method Not Allowed', {
      headers: {
        Allow: 'POST',
        ...corsHeaders
      },
      status: 405
    });
  }
}

export async function OPTIONS(request: Request) {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}
