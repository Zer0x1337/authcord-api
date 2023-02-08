import discord
import mysql.connector

intents = discord.Intents.all()

class AuthBot(discord.Client):
    def __init__(self, intents, *args, **kwargs):
        super().__init__(intents=intents, *args, **kwargs)
        self.db = mysql.connector.connect(
            host='localhost',
            user='root',
            password='8d0a4b24eccf55cedc494b612732678a',
            database='authcord',
            auth_plugin='mysql_native_password'
        )

    async def on_message(self, message):
        if message.author == self.user:
            return
        
        if message.content.startswith("!check"):
            params = message.content.split()
            hwid = params[1]
            apikey = params[2]
            apphash = params[3]

            cursor = self.db.cursor()
            query = "SELECT COUNT(*) FROM logins WHERE hwid=%s AND apikey=%s AND apphash=%s"
            cursor.execute(query, (hwid, apikey, apphash))
            result = cursor.fetchone()

            if result is None or result[0] == 0:
                response = "Invalid"
            else:
                response = "Valid " + hwid
            await message.channel.send(response)

            cursor.close()

        elif message.content.startswith('!register'):
            params = message.content.split()
            param = params[1]
            apikey = params[2]
            userid = params[3]
            apphash = params[4]

            cursor = self.db.cursor()
            query = f'INSERT INTO `logins` (hwid, id, apikey, apphash) VALUES (%s, %s, %s, %s)'
            checker = 'SELECT COUNT(*) FROM logins WHERE hwid=%s AND apikey=%s AND apphash=%s'
            cursor.execute(checker, (param, apikey, apphash))
            result = cursor.fetchone()

            if result[0] > 0:
                response = 'Failed'
            else:
                cursor.execute(query, (param, userid, apikey, apphash))
                self.db.commit()
                response = 'Success ' + param

            await message.channel.send(response)

            cursor.close()

        elif message.content.startswith('!delete'):
            params = message.content.split()
            param = params[1]
            apikey = params[2]
            apphash = params[3]

            cursor = self.db.cursor()
            query = f'DELETE FROM `logins` WHERE hwid=%s AND apikey=%s AND apphash=%s'
            cursor.execute(query, (param, apikey, apphash))
            self.db.commit()

            cursor.close()

auth_bot = AuthBot(intents)
auth_bot.run('MTA1OTY0OTk4MjI4NzgzOTMxMw.GsvJcC.A7sUIBKk0DruMfVgCktyPn0lfIL4rkP1A47Ugk')
