<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">

    <title>{{ page_title }}</title>

    <link rel="stylesheet" href="{{ url('static', filename='style.css') }}">
  </head>

  <body>
    <main>
      <h2 style="text-align: center;">{{ page_title }}</h2>

      <form method="post">
        <label for="admin-password">Admin password</label>
        <input id="admin-password" name="admin-password" type="password" required>

        <p>-------------------------------------</p>

        <label for="username">Username</label>
        <input id="username" name="username" value="{{ get('username', '') }}" type="text" required autofocus>

        <label for="email">E-Mail</label>
        <input id="email" name="email" value="{{ get('email', '') }}" type="email" required autofocus>

        <label for="group">Group ({{ groups }})</label>
        <input id="group" name="group" value="{{ get('group', '') }}" type="text" required autofocus>

        <button type="submit">Create account</button>
      </form>

      <div class="alerts">
        %for type, text in get('alerts', []):
          <div class="alert {{ type }}">{{ text }}</div>
        %end
      </div>
    </main>
  </body>
</html>
