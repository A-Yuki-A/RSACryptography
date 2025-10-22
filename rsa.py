import re
import base64
import binascii
import streamlit as st
import streamlit.components.v1 as components

# --- ページ設定 ---
st.set_page_config(page_title="PrimeGuard RSA")

# --- 文字集合（A-Z と 0-9 をサポート）---
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
CHAR_TO_VAL = {ch: i for i, ch in enumerate(ALPHABET)}
VAL_TO_CHAR = list(ALPHABET)
ALPHABET_DESC = "A–Z と 0–9 のみ（最大5文字）"

# --- ヘルパー関数 ---
def generate_primes(n: int):
    sieve = [True] * (n + 1)
    sieve[0:2] = [False, False]
    for i in range(2, int(n**0.5) + 1):
        if sieve[i]:
            for j in range(i * i, n + 1, i):
                sieve[j] = False
    return [i for i, ok in enumerate(sieve) if ok]

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a: int, m: int):
    # 拡張ユークリッド互除法
    def egcd(x, y):
        if y == 0:
            return (1, 0, x)
        u, v, g = egcd(y, x % y)
        return (v, u - (x // y) * v, g)
    x, _, g = egcd(a, m)
    return x % m if g == 1 else None

def auto_select_e(phi: int, p: int, q: int) -> int:
    """
    教材用：5001〜5999 から φ(n) と互いに素、かつ p,q と異なる
    最小の e を自動選択。
    """
    for i in range(5001, 6000):
        if gcd(i, phi) == 1 and i not in (p, q):
            return i
    raise ValueError("条件を満たす e が見つかりません。p, q を変更してください。")

def encrypt_blocks(plaintext: str, n: int, e: int) -> str:
    """ALPHABET 上の文字を1文字ずつ RSA で暗号化し、Base64 文字列で返す。"""
    size = (n.bit_length() + 7) // 8
    cb = b''.join(
        pow(CHAR_TO_VAL[c], e, n).to_bytes(size, 'big')
        for c in plaintext
    )
    return base64.b64encode(cb).decode()

def decrypt_blocks(b64: str, n: int, d: int) -> str:
    """Base64 暗号文を復号し、ALPHABET の文字列に戻す。"""
    cb = base64.b64decode(b64)
    size = (n.bit_length() + 7) // 8
    if size == 0 or len(cb) % size != 0:
        raise ValueError("ブロック長が一致しません（鍵 n が違う可能性）。")
    chars = []
    for i in range(0, len(cb), size):
        block = cb[i:i + size]
        m = pow(int.from_bytes(block, 'big'), d, n)
        if not (0 <= m < len(ALPHABET)):
            raise ValueError("復号値が想定範囲外です（鍵の組み合わせを確認）。")
        chars.append(VAL_TO_CHAR[m])
    return ''.join(chars)

# --- 素数リスト (5000～6000) ---
primes = [p for p in generate_primes(6000) if 5000 <= p <= 6000]

# --- セッション初期化 ---
for key in ['n', 'e', 'd', 'cipher_str', 'done_recv', 'done_solo']:
    if key not in st.session_state:
        st.session_state[key] = False if key.startswith('done_') else None

# --- アプリタイトル & 説明 ---
st.title("PrimeGuard RSA")
st.markdown(
    """
RSA暗号ではまず2つの大きな素数 p, q を用意し、n = p × q を計算して鍵の基礎となる
　公開鍵 (n, e): メッセージを暗号化する鍵。e は φ(n)=(p−1)(q−1) と互いに素な自然数  
　秘密鍵 (n, d): メッセージを復号する鍵。d は e × d ≡ 1 (mod φ(n)) を満たす自然数

ここでは **e は自動選択**（最小の有効な値）にして、学習の負担を減らします。

暗号化: C ≡ M^e mod n  
復号: M ≡ C^d mod n

> 教材上の注意: 体験用としてパディングなしで1文字ずつ処理します（実運用ではOAEP等を用います）。
"""
)

st.subheader("役割を選択してください")
role = st.radio("", ["受信者", "送信者", "一人で行う"], horizontal=True)
st.markdown("---")

# ========== 受信者モード ==========
if role == "受信者":
    st.header("1. 鍵生成（受信者）")
    st.caption("p, q を選ぶだけで、公開鍵 e は自動的に決まります。")

    c1, c2, c3 = st.columns(3)
    with c1:
        p = st.selectbox("素数 p", primes, key='recv_p')
    with c2:
        q = st.selectbox("素数 q", primes, key='recv_q')

    # e の自動候補（プレビュー）
    phi = (p - 1) * (q - 1)
    e_auto = None
    valid_now = p != q
    if valid_now:
        try:
            e_auto = auto_select_e(phi, p, q)
            st.caption(f"現在の e（自動候補）: {e_auto} / φ(n)={phi}")
        except ValueError as _:
            st.caption(f"現在の e（自動候補）: なし / φ(n)={phi}")

    if st.button("鍵生成", key='recv_gen'):
        if p == q:
            st.error("p と q は異なる素数を選んでください。")
        else:
            try:
                e = auto_select_e(phi, p, q)
                n = p * q
                d = mod_inverse(e, phi)
                if d is None:
                    st.error("d（逆元）が求まりませんでした。p, q を変更してください。")
                else:
                    st.session_state.update({'n': n, 'e': e, 'd': d, 'done_recv': True})
                    st.session_state['dec_n'] = str(n)
                    st.session_state['dec_d'] = str(d)
                    st.success("鍵生成完了。以下の値をコピーしてください。")
            except ValueError as ve:
                st.error(str(ve))

    if st.session_state.done_recv:
        # 鍵表示とコピーボタン
        for label, val in [("公開鍵 n", st.session_state.n),
                           ("公開鍵 e", st.session_state.e),
                           ("秘密鍵 d", st.session_state.d)]:
            col, btn = st.columns([3, 1])
            col.write(f"{label}: {val}")
            with btn:
                components.html(
                    f"<button style=\"border:none;background:none;padding:0;color:blue;cursor:pointer;\" onclick=\"navigator.clipboard.writeText('{val}')\">Copy</button>",
                    height=30
                )

        st.markdown("---")
        # 復号ステップ
        st.header("2. 復号（受信者）")
        st.caption("秘密鍵は (n, d) ですが、ここでは復号に必要な d を入力します。")
        d1, d2, d3 = st.columns(3)
        with d1:
            n_in = st.text_input("公開鍵 n", value=st.session_state.get('dec_n', "") or "", key='dec_n')
        with d2:
            d_in = st.text_input("秘密鍵 d", value=st.session_state.get('dec_d', "") or "", key='dec_d')
        with d3:
            c_in = st.text_area("暗号文 (Base64)", key='dec_c')

        if st.button("復号", key='dec_btn'):
            try:
                nv, dv = int(n_in), int(d_in)
                msg = decrypt_blocks(c_in, nv, dv)
                st.success(f"復号結果: {msg}")
            except ValueError as ve:
                st.error(str(ve))
            except binascii.Error:
                st.error("Base64 の形式が正しくありません。")
            except Exception as e2:
                st.error(f"復号に失敗しました: {e2}")

# ========== 送信者モード ==========
elif role == "送信者":
    st.header("1. 暗号化（送信者）")
    st.caption(f"受信者の公開鍵を入力してください。平文は {ALPHABET_DESC}。")
    s1, s2, s3 = st.columns(3)
    with s1:
        n_in = st.text_input("公開鍵 n", value=str(st.session_state.get('n') or ""), key='enc_n')
    with s2:
        e_in = st.text_input("公開鍵 e", value=str(st.session_state.get('e') or ""), key='enc_e')
    with s3:
        plain = st.text_input(f"平文 ({ALPHABET_DESC})", max_chars=5, key='enc_msg')

    if st.button("暗号化", key='enc_btn'):
        try:
            nv, ev = int(n_in), int(e_in)
            plain_upper = (plain or "").upper()
            if not re.fullmatch(r"[A-Z0-9]{1,5}", plain_upper):
                st.error(f"平文は {ALPHABET_DESC} で入力してください。")
            else:
                b64 = encrypt_blocks(plain_upper, nv, ev)
                st.subheader("暗号文 (Base64)")
                st.code(b64)
                st.session_state.cipher_str = b64
        except ValueError:
            st.error("n や e が整数ではありません。")
        except Exception as e:
            st.error(f"暗号化に失敗しました: {e}")

# ========== 一人で行うモード ==========
elif role == "一人で行う":
    st.header("1. 鍵生成 → 2. 暗号化 → 3. 復号")

    # --- 授業用の説明（流れの冒頭に配置） ---
    c1, c2, _ = st.columns(3)
    with c1:
        p = st.selectbox("素数 p", primes, key='solo_p')
    with c2:
        q = st.selectbox("素数 q", primes, key='solo_q')

    phi1 = (p - 1) * (q - 1)
    e_auto1 = None
    valid_now = p != q
    if valid_now:
        try:
            e_auto1 = auto_select_e(phi1, p, q)
            st.caption(f"現在の e（自動候補）: {e_auto1} / φ(n)={phi1}")
        except ValueError as _:
            st.caption(f"現在の e（自動候補）: なし / φ(n)={phi1}")

    if st.button("鍵生成", key='solo_gen'):
        if p == q:
            st.error("p と q は異なる素数を選んでください。")
        else:
            try:
                e = auto_select_e(phi1, p, q)
                n1 = p * q
                d1 = mod_inverse(e, phi1)
                if d1 is None:
                    st.error("d（逆元）が求まりませんでした。p, q を見直してください。")
                else:
                    st.session_state.update({'n': n1, 'e': e, 'd': d1, 'done_solo': True})
                    st.success("鍵生成完了。下に表示された値をコピーして、次の欄に貼り付けてください。")
            except ValueError as ve:
                st.error(str(ve))

    if st.session_state.done_solo:
        # 鍵表示とコピー（自動入力はしない）
        for label, val in [("公開鍵 n", st.session_state.n),
                           ("公開鍵 e", st.session_state.e),
                           ("秘密鍵 d", st.session_state.d)]:
            col, btn = st.columns([3, 1])
            col.write(f"{label}: {val}")
            with btn:
                components.html(
                    f"<button style=\"border:none;background:none;padding:0;color:blue;cursor:pointer;\" onclick=\"navigator.clipboard.writeText('{val}')\">Copy</button>",
                    height=30
                )

        st.info("手順: 上の n, e, d の値をコピーし、下の各欄に貼り付けてください。")
        st.markdown("---")

        # 暗号化
        st.header("2. 暗号化")
        st.caption(f"平文は {ALPHABET_DESC}。上の公開鍵 n, e をコピーして貼り付けてください。")
        oc1, oc2, oc3 = st.columns(3)
        with oc1:
            n_enc = st.text_input("公開鍵 n", value="", placeholder="上で生成した n を貼り付け", key='solo_enc_n')
        with oc2:
            e_enc = st.text_input("公開鍵 e", value="", placeholder="上で生成した e を貼り付け", key='solo_enc_e')
        with oc3:
            plain1 = st.text_input(f"平文 ({ALPHABET_DESC})", max_chars=5, key='solo_plain1')

        if st.button("暗号化", key='solo_enc_btn'):
            try:
                nv, ev = int(n_enc), int(e_enc)
                plain_upper = (plain1 or "").upper()
                if not re.fullmatch(r"[A-Z0-9]{1,5}", plain_upper):
                    st.error(f"平文は {ALPHABET_DESC} で入力してください。")
                else:
                    b64 = encrypt_blocks(plain_upper, nv, ev)
                    st.subheader("暗号文 (Base64)")
                    st.code(b64)
                    st.session_state.cipher_str = b64
            except ValueError:
                st.error("n や e が整数ではありません。")
            except Exception as e:
                st.error(f"暗号化に失敗しました: {e}")

        st.markdown("---")

        # 復号
        st.header("3. 復号")
        st.caption("秘密鍵は (n, d) です。上の値をコピーして貼り付けてください。")
        dc1, dc2, dc3 = st.columns(3)
        with dc1:
            n_dec = st.text_input("公開鍵 n", value="", placeholder="上で生成した n を貼り付け", key='solo_dec_n')
        with dc2:
            d_dec = st.text_input("秘密鍵 d", value="", placeholder="上で生成した d を貼り付け", key='solo_dec_d')
        with dc3:
            ciph = st.text_area("暗号文 (Base64)", value="", placeholder="上で得た暗号文を貼り付け", key='solo_dec_c')

        if st.button("復号", key='solo_dec_btn'):
            try:
                nn, dd = int(n_dec), int(d_dec)
                msg = decrypt_blocks(ciph, nn, dd)
                st.success(f"復号結果: {msg}")
            except ValueError as ve:
                st.error(str(ve))
            except binascii.Error:
                st.error("Base64 の形式が正しくありません。")
            except Exception as e:
                st.error(f"復号に失敗しました: {e}")
