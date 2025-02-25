docker compose up -d;<br/>
alembic revision --autogenerate -m "Migration";<br/>
alembic upgrade head;<br/>

uvicorn app.main:app --reload --port 8000; (for authorization_microservice) <br/>
uvicorn main:app --reload --port 8001; (for autorization_microservice_notification)<br/>

docker compose down -v;<br/>
docker compose ps;<br/>
docker compose logs kafka;<br/>
docker exec -it kafka kafka-topics --list --bootstrap-server kafka:9093;<br/>
