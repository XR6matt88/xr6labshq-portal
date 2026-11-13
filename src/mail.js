export async function sendMagicLinkEmail(env, toEmail, magicUrl) {
  const fromEmail = env.FROM_EMAIL || 'hq@ac.xr6labs.com';
  const apiUrl = env.ZEPTO_API_URL || 'https://api.zeptomail.com/v1.1/email';

  if (!env.ZEPTO_API_KEY) {
    throw new Error('ZEPTO_API_KEY belum ditetapkan dalam Secrets.');
  }

  const payload = {
    from: {
      address: fromEmail,
      name: 'XR6 Labs HQ – Research & Engineering'
    },
    to: [
      {
        email_address: {
          address: toEmail
        }
      }
    ],
    subject: 'Pautan Pengesahan Log Masuk / Login Verification – XR6 Labs HQ',
    htmlbody: `
      <div style="font-family: Arial, sans-serif; background-color: #081210; color: #F1F5F4; padding: 28px; border-radius: 12px; max-width: 560px; margin: auto; border: 1px solid #1A3831;">
        <p style="color: #D7B46A; font-size: 20px; text-align: center; margin-bottom: 16px;">بِسْمِ ٱللَّهِ ٱلرَّحْمَـٰنِ ٱلرَّحِيمِ</p>
        <h2 style="color: #39E58C; margin-top: 0;">XR6 Labs HQ – Research &amp; Engineering</h2>
        <p style="line-height: 1.6; color: #D1DBD8;">
          Assalamualaikum &amp; Salam Sejahtera,<br><br>
          Sila klik butang di bawah untuk mengesahkan alamat e-mel anda dan log masuk ke portal penyelidik <strong>XR6 Labs HQ</strong>. Pautan ini sah selama <strong>15 minit</strong> sahaja.
        </p>
        <div style="text-align: center; margin: 26px 0;">
          <a href="${magicUrl}" style="background-color: #FF6A00; color: #081210; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
            Sahkan &amp; Log Masuk / Verify &amp; Login
          </a>
        </div>
        <p style="font-size: 12px; color: #8FA39E; line-height: 1.5;">
          Jika anda tidak meminta pautan ini, sila abaikan e-mel ini.<br>
          XR6 Labs HQ • 26A, Kg. Banggol Petai, 06700 Pendang, Kedah Darul Aman, Malaysia.
        </p>
      </div>
    `
  };

  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': env.ZEPTO_API_KEY
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`ZeptoMail Error (${response.status}): ${errText}`);
  }

  return true;
}
