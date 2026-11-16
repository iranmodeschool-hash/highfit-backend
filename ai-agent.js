const cron = require('node-cron');
const axios = require('axios');

const API_BASE = 'https://www.highfit.ir';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AI_API_KEY = process.env.AI_API_KEY;

async function generateAndPostArticle() {
  console.log('🤖 [مرحله ۱] ربات بیدار شد...');
  
  try {
    // ۱. لاگین
    console.log('⏳ در حال لاگین به سایت...');
    const loginRes = await axios.post(`${API_BASE}/api/admin/login`, {
      username: ADMIN_EMAIL, password: ADMIN_PASSWORD
    });
    const token = loginRes.data.token;
    console.log('✅ لاگین موفق بود.');

    // ۲. تماس با هوش مصنوعی
    console.log('🧠 [مرحله ۲] در حال تماس با گوگل...');
    const prompt = `یک مقاله ۵۰۰ کلمه‌ای درباره "پوشاک مدارس" بنویس. خروجی فقط JSON:
    { "title": "عنوان", "summary": "خلاصه", "body": "<p>متن</p>" }`;

    let aiData;
    try {
      const aiRes = await axios.post('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', {
        model: 'gemini-2.0-flash',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.7,
        response_format: { type: "json_object" }
      }, {
        headers: { 'Authorization': `Bearer ${AI_API_KEY}`, 'Content-Type': 'application/json' }
      });
      aiData = aiRes.data;
    } catch (aiError) {
      console.error('❌ خطا در تماس با گوگل:', aiError.response ? JSON.stringify(aiError.response.data) : aiError.message);
      throw new Error('تماس با هوش مصنوعی برقرار نشد.');
    }

    const article = JSON.parse(aiData.choices[0].message.content);
    console.log(`📝 موضوع مقاله: ${article.title}`);

    // ۳. گرفتن عکس
    console.log('🖼️ [مرحله ۳] در حال دانلود عکس...');
    let imageBuffer;
    try {
      const imageRes = await axios.get('https://picsum.photos/800/600', { responseType: 'arraybuffer' });
      imageBuffer = Buffer.from(imageRes.data, 'binary');
    } catch (imgError) {
      console.error('❌ خطا در دانلود عکس:', imgError.message);
      throw new Error('دانلود عکس انجام نشد.');
    }
    
    // ۴. آپلود عکس
    console.log('☁️ [مرحله ۴] در حال آپلود عکس به سایت...');
    const uploadUrlRes = await axios.post(`${API_BASE}/api/files/upload-url`, {
      size: imageBuffer.length, contentType: 'image/jpeg', name: `ai-${Date.now()}.jpg` 
    }, { headers: { 'x-admin-token': token } });
    
    const uploadData = uploadUrlRes.data;
    await axios.put(uploadData.uploadUrl, imageBuffer, { headers: uploadData.headers });
    
    const commitRes = await axios.post(`${API_BASE}/api/files/commit`, {
      uploadId: uploadData.uploadId, name: `ai-${Date.now()}.jpg`
    }, { headers: { 'x-admin-token': token } });
    
    const finalImageUrl = commitRes.data.url;
    console.log('✅ عکس آپلود شد:', finalImageUrl);

    // ۵. ثبت مقاله
    console.log('🚀 [مرحله ۵] در حال ثبت مقاله در سایت...');
    await axios.post(`${API_BASE}/api/admin/articles`, {
      id: `ai-article-${Date.now()}`,
      title: article.title, summary: article.summary, body: article.body,
      image: finalImageUrl, date: new Date().toISOString()
    }, { headers: { 'x-admin-token': token } });
    
    console.log('🎉 مقاله جدید با موفقیت در سایت منتشر شد!');

  } catch (error) {
    console.error('❌ خطای کلی:', error.message);
    throw new Error(error.message); 
  }
}

cron.schedule('0 8 * * *', () => { generateAndPostArticle(); }, { timezone: "Asia/Tehran" });
console.log('⏳ ربات فعال شد.');
module.exports = { generateAndPostArticle };
