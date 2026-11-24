// 个人主体小程序登录页：pages/login/login
// 小程序码 scene 里带上鉴权函数的 state（base64url），扫码进入后回传 code 换 token
Page({
  data: { status: '正在登录…', token: '' },
  onLoad(options) {
    const state = options.scene ? decodeURIComponent(options.scene) : ''
    if (!state) { this.setData({ status: '缺少登录凭据' }); return }
    wx.login({
      success: (res) => {
        if (!res.code) { this.setData({ status: 'wx.login 失败' }); return }
        wx.request({
          url: 'https://auth.example.com/mini/code',
          method: 'POST',
          header: { 'content-type': 'application/json' },
          data: { code: res.code, state },
          success: (r) => {
            if (r.statusCode === 200 && r.data.token) {
              this.setData({ status: '登录成功', token: r.data.token })
              // 同一台设备可直接跳回业务；跨设备则展示 token 供复制
              wx.setClipboardData({ data: r.data.token })
            } else if (r.statusCode === 403) {
              this.setData({ status: '账号不在白名单，请联系管理员' })
            } else {
              this.setData({ status: '鉴权失败：' + (r.data.error || r.statusCode) })
            }
          },
          fail: () => this.setData({ status: '网络错误' })
        })
      }
    })
  },
  copyToken() { wx.setClipboardData({ data: this.data.token }) }
})
