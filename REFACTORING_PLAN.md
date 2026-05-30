# Kế hoạch Refactor Hệ thống Phát hiện Bất thường & Giải thích (Explainability)

## 1. Mục tiêu bài toán và hướng tiếp cận tổng quát
Mục tiêu chính là chuyển đổi hệ thống hiện tại sang một giải pháp thông minh hơn, có khả năng không chỉ dự đoán mà còn **giải thích** được lý do tại sao một request bị coi là bất thường.

- **Giải thích bằng tương đồng**: Sử dụng Vector Search để tìm các request tương tự trong quá khứ (XSS, SQLi, v.v.) để làm bằng chứng.
- **Tốc độ thực tế**: Tối ưu hóa hiệu năng để hệ thống có thể chạy song song với IDS, đảm bảo phát hiện kịp thời.
- **Kiến trúc linh hoạt**: Thiết kế dạng module/adapter để có thể áp dụng cho nhiều nguồn dữ liệu khác nhau (Nginx, Apache, System logs).

## 2. Kiến trúc Hệ thống & Luồng dữ liệu (Architecture & Pipeline)

### Sơ đồ Luồng dữ liệu (Data Pipeline)
```mermaid
graph LR
    A[Raw Log] --> B[Parser]
    B --> C[Normalizer]
    C --> D[Preprocessor]
    D --> E[Embedding Engine - Sinh Vector]
    E --> F[(MongoDB Atlas)]
    F --> G[Tier 1: Anomaly Filtering]
    F --> H[Tier 2: Attack Classification]
    F --> I[Explainability via Vector Index]
```

### Hạ tầng Dữ liệu (MongoDB Atlas)
- **URI**: `mongodb+srv://duchung04st_db_user:[PASSWORD]@cluster0.chngdtb.mongodb.net/?appName=Cluster0`
- **Database**: `security_logs`
- **Collection**: `unified_logs` - lưu trữ log đã chuẩn hóa và vector tương ứng.
- **Indexing**: 
    - **Search Index**: Tìm kiếm text truyền thống.
    - **Vector Index**: Cấu hình trên Atlas phục vụ truy vấn Top-K similarity (ANN).

## 3. Tiền xử lý log và trích xuất đặc trưng
- **Chuẩn hóa (Normalization)**: Tách dòng, xử lý các khác biệt về định dạng giữa các web server.
- **Trích xuất Đặc trưng (Feature Extraction)**:
    - **Fixed Features**: Độ dài request, số ký tự đặc biệt, cấu trúc URL, entropy.
    - **Embedding Engine**: Chuyển đổi dữ liệu log sang Vector Space.

## 4. Kiến trúc Hai tầng Mô hình (Two-Tier Model)
- **Tầng 1: Lọc Bất thường (Anomaly Filtering)**
    - Sử dụng mô hình không giám sát (Unsupervised) để lọc bỏ log bình thường.
- **Tầng 2: Phân loại & Định danh (Deep Classification)**
    - Sử dụng Vector Search trên MongoDB Atlas để tìm mẫu tấn công tương đồng và định danh loại tấn công.

## 5. Danh sách Công việc (Action Items)
1. [x] **Configuration**: Thiết lập biến môi trường cho MongoDB URI và DB Name. (Hoàn thành qua `.env.template` và `src/main.py`)
2. [x] **Pipeline**: Cập nhật `src/normalizer/` và `src/preprocessor/` để khớp với schema `unified_logs`. (Đã tích hợp vào `LogPipeline`)
3. [x] **Embedding**: Triển khai Embedding Engine sinh vector cho mỗi request. (Đã triển khai bản stub)
4. [ ] **Atlas Setup**: Tạo **Vector Search Index** trên MongoDB Atlas cho collection `unified_logs`.        
5. [x] **Detection**: Triển khai Tier 1 Filter và Tier 2 Similarity Engine. (Tier 1 Rule-based đã sẵn sàng, Tier 2 đã chuẩn bị vector trong DB)
6. [ ] **Reporting**: Hiển thị lý do giải thích dựa trên các mẫu tương đồng tìm được từ DB.

