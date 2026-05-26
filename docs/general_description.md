# Project: Web Server Log Parser & Detection Pipeline

## 1. Mục tiêu dự án

Xây dựng một hệ thống xử lý log Web Server hoàn chỉnh, có khả năng:

1. Đọc file access log từ Apache, Nginx, IIS.
2. Thu thập raw log lines một cách ổn định.
3. Parse các trường quan trọng trong log.
4. Chuẩn hóa dữ liệu về một common schema thống nhất.
5. Tiền xử lý HTTP request để phục vụ detection và training sau này.
6. Áp dụng rule-based detector làm baseline ban đầu.
7. Trích xuất các feature thủ công cơ bản.
8. Xuất dữ liệu đã chuẩn hóa, alert, report để dùng cho:
   - phân tích bảo mật,
   - tích hợp SIEM,
   - train model AI/ML ở module riêng.

Lưu ý quan trọng:

Trong giai đoạn này, KHÔNG triển khai module AI/NLP Detector chính thức.

Module AI/NLP hoặc ML truyền thống như TF-IDF, character n-gram, Logistic Regression, SVM, Isolation Forest sẽ được xử lý ở giai đoạn riêng sau khi pipeline dữ liệu đã ổn định.

Pipeline hiện tại chỉ cần tạo output sạch, nhất quán, dễ dùng cho module train/evaluate sau này.

---

## 2. Phạm vi triển khai hiện tại

Triển khai các module chính:

```text
[1] Log Collector
[2] Parser
[3] Normalizer
[4] Request Preprocessor
[5] Rule-based Detector
[6] Hand-crafted Feature Extractor
[7] Risk Scoring & Post-processing
[8] Exporter / Report