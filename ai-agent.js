const cron = require('node-cron');

const API_BASE = 'https://www.highfit.ir';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AI_API_KEY = process.env.AI_API_KEY;

async function generateAndPostArticle() {
  console.log('🤖 ربات بیدار شد و شروع به کار کرد...');
  try {
    // ۱. لاگین به سایت
    const loginRes = await fetch(`${API_BASE}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: ADMIN_EMAIL, password: ADMIN_PASSWORD })
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok) throw new Error('لاگین نشد: ' + JSON.stringify(loginData));
    const token = loginData.token;
    console.log('✅ لاگین موفق بود.');

    // ۲. نوشتن مقاله با هوش مصنوعی
    console.log('🧠 هوش مصنوعی در حال نوشتن مقاله است...');
    const prompt = `یک مقاله ۵۰۰ کلمه‌ای درباره "پوشاک مدارس" یا "فرم مدارس" بنویس. خروجی را دقیقاً به فرمت JSON زیر بده (بدون هیچ متن اضافه‌ای):
    {
      "title": "عنوان جذاب مقاله",
      "summary": "یک خلاصه ۲ جمله‌ای",
      "body": "<p>متن کامل مقاله با تگ‌های HTML مثل h2 و p</p>"
    }`;

    const aiRes = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${AI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'deepseek-chat',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.7
      })
    });
    const aiData = await aiRes.json();
    if (!aiRes.ok) throw new Error('هوش مصنوعی جواب نداد: ' + JSON.stringify(aiData));
    
    const text = aiData.choices[0].message.content;
    const cleanJson = text.replace(/```json/g, '').replace(/```/g, '').trim();
    const article = JSON.parse(cleanJson);
    console.log(`📝 موضوع مقاله: ${article.title}`);

    // ۳. آماده‌سازی عکس
    console.log('🖼️ در حال گرفتن عکس...');
    const imageRes = await fetch('https://picsum.photos/800/600');
    const imageBuffer = Buffer.from(await imageRes.arrayBuffer());
    
    // ۴. آپلود ۳ مرحله‌ای عکس
    const uploadUrlRes = await fetch(`${API_BASE}/api/files/upload-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
      body: JSON.stringify({ size: imageBuffer.length, contentType: 'image/jpeg', name: `ai-${Date.now()}.jpg` })
    });
    const uploadData = await uploadUrlRes.json();
    
    await fetch(uploadData.uploadUrl, { method: 'PUT', headers: uploadData.headers, body: imageBuffer });
    
    const commitRes = await fetch(`${API_BASE}/api/files/commit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
      body: JSON.stringify({ uploadId: uploadData.uploadId, name: `ai-${Date.now()}.jpg` })
    });
    const commitData = await commitRes.json();
    console.log('✅ عکس آپلود شد:', commitData.url);

    // ۵. ثبت نهایی مقاله در سایت
    const postRes = await fetch(`${API_BASE}/api/admin/articles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-token': token },
      body: JSON.stringify({
        id: `ai-article-${Date.now()}`,
        title: article.title,
        summary: article.summary,
        body: article.body,
        image: commitData.url,
        date: new Date().toISOString()
      })
    });
    
    if (!postRes.ok) throw new Error('ثبت مقاله در سایت انجام نشد.');
    console.log('🎉 مقاله جدید با موفقیت در سایت منتشر شد!');

  } catch (error) {
    console.error('❌ خطا:', error.message);
  }
}

// زمان‌بندی: هر روز ساعت ۸ صبح
cron.schedule('0 8 * * *', () => {
  generateAndPostArticle();
}, { timezone: "Asia/Tehran" });

console.log('⏳ ربات فعال شد و هر روز ساعت ۸ صبح کار می‌کند.');

module.exports = { generateAndPostArticle };
