const { Bot } = require("grammy")
const fetch = require("node-fetch")
const sharp = require("sharp")
const fs = require("fs")
const bot = new Bot("7061646549:AAHqatuzp07loskOZXrN8-QTZopXaOuh5Cw")

bot.on("message:new_chat_members", async ctx => {
  const user = ctx.message.new_chat_members[0]
  const photos = await ctx.api.getUserProfilePhotos(user.id, { limit: 1 })
  let avatarBuffer = Buffer.from("")
  if (photos.total_count > 0) {
    const fileId = photos.photos[0][0].file_id
    const fileLink = await ctx.api.getFileLink(fileId)
    const res = await fetch(fileLink.href)
    avatarBuffer = await res.buffer()
  } else {
    const res = await fetch("https://via.placeholder.com/200")
    avatarBuffer = await res.buffer()
  }

  const circle = await sharp(avatarBuffer).resize(200, 200).composite([
    { input: Buffer.from(`<svg><circle cx="100" cy="100" r="100"/></svg>`), blend: "dest-in" }
  ]).png().toBuffer()

  const svgText = `
    <svg width="1080" height="720">
      <style>
        .name { fill: white; font-size: 48px; font-family: sans-serif; }
        .info { fill: #ccc; font-size: 32px; font-family: sans-serif; }
      </style>
      <text x="250" y="100" class="name">${user.first_name || "New User"}</text>
      <text x="250" y="160" class="info">Username: @${user.username || "N/A"}</text>
      <text x="250" y="210" class="info">ID: ${user.id}</text>
    </svg>
  `
  const svgBuffer = Buffer.from(svgText)

  const finalImage = await sharp({
    create: {
      width: 1280,
      height: 720,
      channels: 3,
      background: "#111"
    }
  }).composite([
    { input: circle, left: 20, top: 20 },
    { input: svgBuffer, top: 0, left: 0 }
  ]).jpeg().toBuffer()

  fs.writeFileSync("welcome.jpg", finalImage)
  await ctx.replyWithPhoto({ source: "welcome.jpg" })
})

bot.start()
