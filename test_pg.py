import asyncio, asyncpg

async def run():
    conn = await asyncpg.connect(user='postgres',password='Fa226021',database='genai_gateway',host='localhost')
    users = await conn.fetch('SELECT username FROM users')
    print([dict(u) for u in users])
    await conn.close()

asyncio.run(run())
