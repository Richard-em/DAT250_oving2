"""Provides all routes for the Social Insecurity application.

This file contains the routes for the application. It is imported by the social_insecurity package.
It also contains the SQL queries used for communicating with the database.
"""

from pathlib import Path

from flask import current_app as app
from flask import flash, redirect, render_template, send_from_directory, url_for

from flask_login import current_user, login_user, logout_user, login_required
from social_insecurity import sqlite, bcrypt, login

from flask import abort  # added
from werkzeug.utils import secure_filename  # added

from social_insecurity import sqlite
from social_insecurity.forms import CommentsForm, FriendsForm, IndexForm, PostForm, ProfileForm

from social_insecurity.user import User

@login.user_loader
def load_user(user_id):
    query = "SELECT * FROM Users WHERE id = :userid;"
    user = sqlite.query(query, {"userid": user_id}, one=True)
    if user:
        return User(user["id"], user["username"], user["password"])
    return None

def register_routes(app):
    @app.route("/", methods=["GET", "POST"])
    @app.route("/index", methods=["GET", "POST"])
    def index():
        """Provides the index page for the application.

        It reads the composite IndexForm and based on which form was submitted,
        it either logs the user in or registers a new user.

        If no form was submitted, it simply renders the index page.
        """
        index_form = IndexForm()
        login_form = index_form.login
        register_form = index_form.register

        if login_form.validate_on_submit() and login_form.submit.data:
            user = User.get_by_username(login_form.username.data)

            if not user:
                flash("Sorry, this user does not exist!", category="warning")
            elif bcrypt.check_password_hash(user.password, login_form.password.data):
                login_user(user, remember=login_form.remember_me.data)
                return redirect(url_for("stream", username=login_form.username.data))
            else:
                flash("Sorry, wrong password!", category="warning")

        elif register_form.validate_on_submit() and register_form.submit.data:
            existing = User.get_by_username(register_form.username.data)
            if existing:
                flash("Username taken", category="warning")
            else:
                hashed_pw = bcrypt.generate_password_hash(register_form.password.data).decode("utf-8")

            insert_user = """
            INSERT INTO Users (username, first_name, last_name, password)
            VALUES (:username, :first_name, :last_name, :password);
            """

            sqlite.query(
                insert_user,
                {
                    "username": register_form.username.data.strip(),
                    "first_name": register_form.first_name.data.strip(),
                    "last_name": register_form.last_name.data.strip(),
                    "password": hashed_pw,
                }
            )
            return redirect(url_for("index"))

        return render_template("index.html.j2", title="Welcome", form=index_form)


    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))


    # Helper for verifying file extension in whitelist
    def allowed_file(filename: str) -> bool:
        if "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower()
        return ext in app.config["ALLOWED_EXTENSIONS"]


    @app.route("/stream/<string:username>", methods=["GET", "POST"])
    @login_required
    def stream(username: str):
        """Provides the stream page for the application.

        If a form was submitted, it reads the form data and inserts a new post into the database.

        Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
        """
        post_form = PostForm()
        user = User.get_by_username(username)
        if user is None:
            flash(f"Stream of user: '{username}' not found.", "warning")
            return redirect(url_for("index"))

        # Added sanitization of filename using secure_filename, and check for resolved path
        # Previous implementation made it trivial for attackers to infect system.
        if post_form.validate_on_submit():
            filename = None
            if post_form.image.data:
                filename = secure_filename(post_form.image.data.filename)
                # Use helper to check if file type in whitelist
                if not allowed_file(filename):
                    abort(400, description="File type not allowed")

                uploads_dir = Path(app.instance_path) / \
                    app.config["UPLOADS_FOLDER_PATH"]
                file_path = uploads_dir / filename

                try:
                    file_path.resolve(strict=False).relative_to(
                        uploads_dir.resolve(strict=True))
                except Exception:
                    abort(400, description="Invalid file path")

                post_form.image.data.save(file_path)

            insert_post = """
                INSERT INTO Posts (u_id, content, image, creation_time)
                VALUES (:user_id, :content, :image_filename, CURRENT_TIMESTAMP);
                """
            sqlite.query(insert_post, {
                        "user_id": user["id"],
                        "content": post_form.content.data.strip(),
                        "image_filename": filename})
            return redirect(url_for("stream", username=username))

        get_posts = """
            SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
            FROM Posts AS p JOIN Users AS u ON u.id = p.u_id
            WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = :user_id) OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = :user_id) OR p.u_id = :user_id
            ORDER BY p.creation_time DESC;
            """
        posts = sqlite.query(get_posts, {"user_id": user["id"]})
        return render_template("stream.html.j2", title="Stream", username=username, form=post_form, posts=posts)


    @app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
    def comments(username: str, post_id: int):
        """Provides the comments page for the application.

        If a form was submitted, it reads the form data and inserts a new comment into the database.

        Otherwise, it reads the username and post id from the URL and displays all comments for the post.
        """
        comments_form = CommentsForm()
        get_user = """
            SELECT *
            FROM Users
            WHERE username = :username;
            """
        user = sqlite.query(get_user, {"username": username}, one=True)

        if comments_form.validate_on_submit():
            insert_comment = """
                INSERT INTO Comments (p_id, u_id, comment, creation_time)
                VALUES (:post_id, :user_id, :comment, CURRENT_TIMESTAMP);
                """
            sqlite.query(insert_comment, {"post_id": post_id,
                                        "user_id": user["id"],
                                        "comment": comments_form.comment.data, })

        get_post = """
            SELECT *
            FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
            WHERE p.id = :post_id;
            """
        get_comments = """
            SELECT DISTINCT *
            FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
            WHERE c.p_id= :post_id
            ORDER BY c.creation_time DESC;
            """
        post = sqlite.query(get_post, {"post_id": post_id}, one=True)
        comments = sqlite.query(get_comments, {"post_id": post_id})
        return render_template(
            "comments.html.j2", title="Comments", username=username, form=comments_form, post=post, comments=comments
        )


    @app.route("/friends/<string:username>", methods=["GET", "POST"])
    def friends(username: str):
        """Provides the friends page for the application.

        If a form was submitted, it reads the form data and inserts a new friend into the database.

        Otherwise, it reads the username from the URL and displays all friends of the user.
        """
        friends_form = FriendsForm()
        get_user = """
            SELECT *
            FROM Users
            WHERE username = :username;
            """
        user = sqlite.query(get_user, {"username": username}, one=True)
        # Added
        if user is None:
            flash(f"User '{username}' not found.", "warning")
            return redirect(url_for("index"))

        if friends_form.validate_on_submit():
            get_friend = """
                SELECT *
                FROM Users
                WHERE username = :friend;
                """
            friend = sqlite.query(
                get_friend, {"friend": friends_form.username.data}, one=True)
            get_friends = """
                SELECT f_id
                FROM Friends
                WHERE u_id = :user_id;
                """
            friends = sqlite.query(get_friends, {"user_id": user["id"]})

            if friend is None:
                flash("User does not exist!", category="warning")
            elif friend["id"] == user["id"]:
                flash("You cannot be friends with yourself!", category="warning")
            elif friend["id"] in [friend["f_id"] for friend in friends]:
                flash("You are already friends with this user!", category="warning")
            else:
                insert_friend = """
                    INSERT INTO Friends (u_id, f_id)
                    VALUES (:user_id, :friend_id);
                    """
                sqlite.query(insert_friend, {
                            "user_id": user["id"], "friend_id": friend["id"]})
                flash("Friend successfully added!", category="success")

        get_friends = """
            SELECT *
            FROM Friends AS f JOIN Users as u ON f.f_id = u.id
            WHERE f.u_id = :user_id AND f.f_id != :user_id;
            """
        friends = sqlite.query(get_friends, {"user_id": user["id"]})
        return render_template("friends.html.j2", title="Friends", username=username, friends=friends, form=friends_form)


    @app.route("/profile/<string:username>", methods=["GET", "POST"])
    def profile(username: str):
        """Provides the profile page for the application.

        If a form was submitted, it reads the form data and updates the user's profile in the database.

        Otherwise, it reads the username from the URL and displays the user's profile.
        """
        profile_form = ProfileForm()
        get_user = """
            SELECT *
            FROM Users
            WHERE username = :username;
        """
        user = sqlite.query(get_user, {"username": username}, one=True)
        if user is None:
            flash(f"User '{username}' not found.", "warning")
            return redirect(url_for("index"))

        if profile_form.validate_on_submit():
            update_profile = """
                UPDATE Users
                SET education = :education,
                    employment = :employment,
                    music = :music,
                    movie = :movie,
                    nationality = :nationality,
                    birthday = :birthday
                WHERE username = :username;
            """
            # Added: stripping input to remove leading and trailing whitespaces
            sqlite.query(
                update_profile,
                {
                    "education": profile_form.education.data.strip(),
                    "employment": profile_form.employment.data.strip(),
                    "music": profile_form.music.data.strip(),
                    "movie": profile_form.movie.data.strip(),
                    "nationality": profile_form.nationality.data.strip(),
                    "birthday": profile_form.birthday.data.strip(),
                    "username": username.strip(),
                }
            )
            return redirect(url_for("profile", username=username))

        return render_template("profile.html.j2", title="Profile", username=username, user=user, form=profile_form)


    # Changed to protect against unathorized access of files
    # Checks for traversal-enabling chars, path within upload dir, existence of file, permitted extension.
    @app.route("/uploads/<string:filename>")
    def uploads(filename):
        """Provides an endpoint for serving uploaded files."""
        uploads_dir = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"]

        if "/" in filename or "\\" in filename or ".." in filename:
            abort(400, description="Invalid filename")

        if filename.startswith("."):
            abort(403, description="Access denied")

        safe_path = uploads_dir / filename

        # Added filetype validation
        # Get whitelist from config, if unable default to no extensions allowed (empty set)
        allowed = app.config.get("ALLOWED_EXTENSIONS", set())
        # Split from right (get file extension)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if allowed and ext not in allowed:
            abort(403, description="File type not allowed")

        try:
            safe_path.resolve(strict=True).relative_to(
                uploads_dir.resolve(strict=True))
        except Exception:
            abort(403, description="Access outside upload directory not allowed")

        if not safe_path.exists():
            abort(404)

        return send_from_directory(uploads_dir, filename)
