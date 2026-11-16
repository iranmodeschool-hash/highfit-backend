const cron = require('node-cron');
const axios = require('axios');

const API_BASE = 'https://www.highfit.ir';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AI_API_KEY = process.env.AI_API_KEY;

async function generateAndPostArticle() {
  console.log('🤖 ربات بیدار شد و شروع به کار کرد...');
  
  try {
    console.log('⏳ در حال لاگین به سایت...');
    const loginRes = await axios.post(`${API_BASE}/api/admin/login`, {
      username: ADMIN_EMAIL, password: ADMIN_PASSWORD
    });
    const token = loginRes.data.token;
    console.log('✅ لاگین موفق بود.');

    console.log('🧠 هوش مصنوعی (GapGPT) در حال نوشتن مقاله است...');
    const prompt = `یک مقاله ۵۰۰ کلمه‌ای درباره "پوشاک مدارس" بنویس. خروجی فقط JSON:
    { "title": "عنوان", "summary": "خلاصه", "body": "<p>متن کامل با تگ‌های HTML</p>" }`;

    const aiRes = await axios.post('https://api.gapgpt.app/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
      response_format: { type: "json_object" }
    }, {
      headers: { 'Authorization': `Bearer ${AI_API_KEY}`, 'Content-Type': 'application/json' }
    });

    const article = JSON.parse(aiRes.data.choices[0].message.content);
    console.log(`📝 موضوع مقاله: ${article.title}`);

    console.log('🖼️ در حال دانلود عکس...');
    const imageRes = await axios.get('https://picsum.photos/800/600', { responseType: 'arraybuffer' });
    const imageBuffer = Buffer.from(imageRes.data, 'binary');
    
    console.log('☁️ در حال آپلود عکس به سایت...');
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

    console.log('🚀 در حال ارسال مقاله به سایت...');
    await axios.post(`${API_BASE}/api/admin/articles`, {
      id: `ai-article-${Date.now()}`,
      title: article.title, summary: article.summary, body: article.body,
      image: finalImageUrl, date: new Date().toISOString()
    }, { headers: { 'x-admin-token': token } });
    
    console.log('🎉 مقاله جدید با موفقیت در سایت منتشر شد!');

  } catch (error) {
    const errorMsg = error.response ? JSON.stringify(error.response.data) : error.message;
    console.error('❌ خطا:', errorMsg);
    throw new Error(errorMsg); 
  }
}

// زمان‌بندی: هر روز ساعت ۸ صبح (cron فقط یک بار اینجا استفاده شده است)
cron.schedule('0 8 * * *', () => { generateAndPostArticle(); }, { timezone: "Asia/Tehran" });
console.log('⏳ ربات فعال شد.');
module.exports = { generateAndPostArticle };
