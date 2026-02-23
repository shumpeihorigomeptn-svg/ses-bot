gcloud builds submit \
  --tag asia-northeast1-docker.pkg.dev/$(gcloud config get-value project)/app/slackbot:latest \
  .


gcloud run deploy slackbot \
  --image asia-northeast1-docker.pkg.dev/$(gcloud config get-value project)/app/slackbot:latest \
  --region asia-northeast1 \
  --allow-unauthenticated \
  --ingress all
