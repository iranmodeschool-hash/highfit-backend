const cron = require('node-cron');
const axios = require('axios');

const API_BASE = 'https://www.highfit.ir';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AI_API_KEY = process.env.AI_API_KEY;

async function generateAndPostArticle() {
  console.log('🤖 ربات بیدار شد و شروع به کار کرد...');
  
  try {
    // ۱. لاگین به سایت
    console.log('⏳ در حال لاگین به سایت...');
    const loginRes = await axios.post(`${API_BASE}/api/admin/login`, {
      username: ADMIN_EMAIL,
      password: ADMIN_PASSWORD
    });
    const token = loginRes.data.token;
    console.log('✅ لاگین موفق بود.');

    // ۲. نوشتن مقاله با هوش مصنوعی گوگل (Gemini)
    console.log('🧠 هوش مصنوعی گوگل در حال نوشتن مقاله است...');
    const prompt = `یک مقاله ۵۰۰ کلمه‌ای درباره "پوشاک مدارس" یا "فرم مدارس" بنویس. خروجی را دقیقاً به فرمت JSON زیر بده (بدون هیچ متن اضافه‌ای، فقط JSON):
    {
      "title": "عنوان جذاب مقاله",
      "summary": "یک خلاصه ۲ جمله‌ای",
      "body": "<p>متن کامل مقاله با تگ‌های HTML مثل h2 و p</p>"
    }`;

    // استفاده از API سازگار با OpenAI گوگل
    const aiRes = await axios.post('https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', {
      model: 'gemini-1.5-flash', // مدل فوق سریع و رایگان گوگل
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.7,
      response_format: { type: "json_object" }
    }, {
      headers: { 'Authorization': `Bearer ${AI_API_KEY}`, 'Content-Type': 'application/json' }
    });

    const text = aiRes.data.choices[0].message.content;
    const article = JSON.parse(text);
    console.log(`📝 موضوع مقاله: ${article.title}`);

    // ۳. آماده‌سازی عکس
    console.log('🖼️ در حال گرفتن عکس...');
    const imageRes = await axios.get('https://picsum.photos/800/600', { responseType: 'arraybuffer' });
    const imageBuffer = Buffer.from(imageRes.data, 'binary');
    
    // ۴. آپلود ۳ مرحله‌ای عکس
    console.log('☁️ در حال آپلود عکس...');
    const uploadUrlRes = await axios.post(`${API_BASE}/api/files/upload-url`, {
      size: imageBuffer.length, 
      contentType: 'image/jpeg', 
      name: `ai-${Date.now()}.jpg` 
    }, { headers: { 'x-admin-token': token } });
    
    const uploadData = uploadUrlRes.data;
    await axios.put(uploadData.uploadUrl, imageBuffer, { headers: uploadData.headers });
    
    const commitRes = await axios.post(`${API_BASE}/api/files/commit`, {
      uploadId: uploadData.uploadId, 
      name: `ai-${Date.now()}.jpg`
    }, { headers: { 'x-admin-token': token } });
    
    const finalImageUrl = commitRes.data.url;
    console.log('✅ عکس آپلود شد:', finalImageUrl);

    // ۵. ثبت نهایی مقاله در سایت
    console.log('🚀 در حال ارسال مقاله به سایت...');
    await axios.post(`${API_BASE}/api/admin/articles`, {
      id: `ai-article-${Date.now()}`,
      title: article.title,
      summary: article.summary,
      body: article.body,
      image: finalImageUrl,
      date: new Date().toISOString()
    }, { headers: { 'x-admin-token': token } });
    
    console.log('🎉 مقاله جدید با موفقیت در سایت منتشر شد!');

  } catch (error) {
    const errorMsg = error.response ? JSON.stringify(error.response.data) : error.message;
    console.error('❌ خطا:', errorMsg);
    throw new Error(errorMsg); 
  }
}

// زمان‌بندی: هر روز ساعت ۸ صبح
cron.schedule('0 8 * * *', () => {
  generateAndPostArticle();
}, { timezone: "Asia/Tehran" });

console.log('⏳ ربات فعال شد و هر روز ساعت ۸ صبح کار می‌کند.');

module.exports = { generateAndPostArticle };
