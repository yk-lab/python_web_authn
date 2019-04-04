# Python & WebAuthn
macOS の touch id (chrome) のみ対応

## 環境構築
```python3
$ pipenv install
```

## 起動方法
```python3
$ pipenv run python3 -m http.server 8000
$ pipenv run python3 app.py
```

## 参考資料
- [Web Authentication (WebAuthn) Credential and Login Demo](https://webauthn.me/)
- [Web Authentication API](https://developer.mozilla.org/ja/docs/Web/API/Web_Authentication_API)
- [Web Authentication: An API for accessing Public Key Credentials Level 1](https://www.w3.org/TR/webauthn/)
- [Web Authentication: An API for accessing Public Key Credentials Level 2](https://w3c.github.io/webauthn/)
- [Yahoo! JAPANでの生体認証の取り組み（FIDO2サーバーの仕組みについて）](https://techblog.yahoo.co.jp/advent-calendar-2018/webauthn/)
- [FIDO2 attestation formatの紹介](https://techblog.yahoo.co.jp/advent-calendar-2018/webauthn-attestation-packed/)
- [Web Authentication API で FIDO U2F(YubiKey) 認証](https://blog.jxck.io/entries/2018-05-15/webauthentication-api.html)

## 今後参考になりそうなこと
- [WebAuthnライブラリ調査めも（PyWebAuthn）](http://kent056-n.hatenablog.com/entry/2019/01/14/210730)
- [TLS 1.3 開発日記 その22 公開鍵暗号の動向](https://kazu-yamamoto.hatenablog.jp/entry/20171114/1510635277)
