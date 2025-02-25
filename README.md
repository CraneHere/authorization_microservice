docker compose up -d;
alembic revision --autogenerate -m "Migration";
alembic upgrade head;

uvicorn app.main:app --reload --port 8000; #authorization_microservice
uvicorn main:app --reload --port 8001; #autorization_microservice_notification

docker compose down -v;
docker compose ps;
docker compose logs kafka;
docker exec -it kafka kafka-topics --list --bootstrap-server kafka:9093;