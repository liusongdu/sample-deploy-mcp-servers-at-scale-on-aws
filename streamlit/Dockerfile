FROM public.ecr.aws/amazonlinux/amazonlinux:latest

RUN dnf update -y
RUN dnf install -y python3.11
RUN dnf install -y python3.11-pip

COPY . .
RUN cat requirements.txt

RUN python3.11 -m pip install -r requirements.txt

CMD ["streamlit", "run", "index.py", "--server.fileWatcherType", "none"]