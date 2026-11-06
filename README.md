# BCCN_ATTT — mã nguồn minh họa cho báo cáo RSA-PSS

Đây là bản dựng lại đầy đủ mã minh họa theo luồng Merchant–Proxy–Issuer và 12 kịch bản KS-01…KS-12 trong báo cáo. Bản dựng cũng bổ sung một số kiểm soát đã được nêu trong phần nhận xét: nonce đúng 128 bit, JSON từ chối khóa trùng, fingerprint chứng thư SHA-256 đầy đủ, chống trùng `MessageID` nguyên tử và CRL X.509 có chữ ký.

> **Chỉ dùng cho học tập/thử nghiệm.** Đây không phải hệ thống thanh toán hay PKI dùng trong production. Chữ ký Merchant không chứng minh chủ thẻ đã đồng ý giao dịch; chữ ký không mã hóa nội dung và không thay thế TLS, 3DS/SCA, xác thực nghiệp vụ hoặc quản lý khóa HSM/KMS.

## Cấu trúc

- `rsa_crypto.py` — RSA-PSS/SHA-256, sinh nonce CSPRNG, băm, canonical JSON phiên bản demo và parser JSON giới hạn 16 KiB, từ chối khóa trùng và số thực.
- `ca_service.py` — CA X.509 một tầng dùng trong demo, chứng thư lá, CRL X.509 được ký và kiểm tra trạng thái thu hồi; CRL demo có thời hạn 1 giờ, tự làm mới khi hết hạn và không thay thế OCSP/CA production.
- `nonce_store.py` — kho nonce/idempotency trong bộ nhớ có khóa đồng thời; adapter Redis tùy chọn dùng Lua để đặt nonce và `MessageID` nguyên tử.
- `audit_log.py` — nhật ký JSONL dạng chuỗi băm; phát hiện sửa bản ghi nhưng **không** chống được quản trị viên có thể viết lại toàn bộ file.
- `he_thong.py` — Merchant, Proxy, Issuer và pipeline xác minh T0–T5.
- `kich_ban/ks_01_…ks_12_*.py` — 12 kịch bản đầu-cuối của báo cáo.
- `run_scenarios.py` — chạy kịch bản, kiểm tra sáu mã lỗi bổ sung, demo luồng và đo primitive mật mã.
- `tests/` — kiểm thử RSA-PSS, schema, chống phát lại, idempotency, đồng thời và audit log.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Chạy toàn bộ 12 kịch bản và sáu kiểm tra đơn vị bổ sung:

```bash
python run_scenarios.py
```

Chạy một kịch bản, demo luồng G1–G8 hoặc benchmark RSA:

```bash
python run_scenarios.py --ks 3
python run_scenarios.py --flow
python run_scenarios.py --bench
```

Chạy kiểm thử tự động:

```bash
pytest -q
```

`--bench` đo các phép toán tuần tự trên một payload nhỏ; số lần/giây in ra là nghịch đảo latency trung bình, **không phải throughput production đo dưới tải**.

## Các quyết định bảo mật trong bản dựng

- Payload gồm đúng bảy trường: `MessageID`, `MerchantID`, `CardToken`, `Amount`, `Currency`, `Timestamp`, `Nonce`.
- Chữ ký dùng RSASSA-PSS với SHA-256, MGF1-SHA-256, salt 32 byte; khóa hoạt động tối thiểu 2048 bit, số mũ công khai 65537.
- Nonce sinh ngẫu nhiên 128 bit (`secrets.token_hex(16)`) và được xác thực định dạng ở Issuer.
- Timestamp UTC phải nằm trong cửa sổ cấu hình; đây là timestamp do Merchant ký, không phải dấu thời gian độc lập được chứng thực.
- `MessageID` được dùng như khóa idempotency 24 giờ; trùng `MessageID` nhưng nonce mới bị từ chối với `DUPLICATE_MESSAGE`.
- Kiểm tra chứng thư ràng buộc fingerprint với registry Merchant; CRL demo là CRL X.509 thật có chữ ký, nhưng CA và khóa đều sinh lại trong mỗi lần chạy. Thời điểm thu hồi được so với đồng hồ verifier (không tin timestamp tự khai của Merchant để lùi qua thu hồi); live request cũng phải có chứng thư còn hiệu lực hiện tại.
- `InMemoryReplayStore` là mặc định cho demo đơn tiến trình; TTL mặc định là 660 giây cho nonce (2 × cửa sổ Timestamp 300 giây, cộng 60 giây đệm) và 24 giờ cho `MessageID`. `RedisReplayStore` cần cài riêng `redis` và cấu hình dịch vụ Redis; lỗi kho sẽ bị từ chối theo nguyên tắc fail-closed. TTL idempotency thực tế phải dài ít nhất bằng cửa sổ retry nghiệp vụ và nên dựa trên trạng thái giao dịch/retention.
- Hash chain audit chỉ giúp phát hiện một số dạng chỉnh sửa. Muốn có chứng cứ bền vững cần kho được bảo vệ, chữ ký/neo ngoài tiến trình, dấu thời gian tin cậy và chính sách lưu trữ phù hợp.

## Giới hạn quan trọng

Canonical JSON trong `rsa_crypto.py` là profile riêng của bài tập, giới hạn kiểu số và chuẩn hóa chuỗi NFC; không tuyên bố tương thích hoàn toàn RFC 8785/JCS. Hai hệ thống độc lập chỉ nên dùng profile này khi thống nhất phiên bản và cùng bộ test vectors. Với triển khai liên thông, hãy dùng implementation JCS đã kiểm thử.

CA chỉ mô phỏng một gốc tin cậy trực tiếp; không có path building tổng quát, OCSP, xoay khóa bền vững, HSM/KMS, TLS, 3DS/SCA, xử lý settlement hay kiểm chứng tuân thủ PCI DSS. Không đưa khóa thật, PAN hoặc dữ liệu khách hàng thật vào ví dụ.
