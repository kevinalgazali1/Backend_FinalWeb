from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from db import get_db, init_app
from flask_cors import CORS
import bcrypt

app = Flask(__name__)
CORS(app)
init_app(app)

app.config['JWT_SECRET_KEY'] = 'secret'  # Ganti dengan kunci rahasia yang kuat
jwt = JWTManager(app)
        
@app.route('/users', methods=['GET', 'POST'])
def manage_users():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM User")
        users = cursor.fetchall()
        return jsonify(users)
    elif request.method == 'POST':
        data = request.get_json()
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        role = data.get('role', 'user')
        cursor.execute(
            "INSERT INTO User (nama_lengkap, nomor_telepon, email, password, role) VALUES (%s, %s, %s, %s, %s)",
            (data['nama_lengkap'], data['nomor_telepon'], data['email'], hashed_password, role)
        )
        db.commit()
        return jsonify({'message': 'User created successfully'}), 201

@app.route('/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
def manage_user(user_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM User WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
            return jsonify(user)
        else:
            return jsonify({'message': 'User not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        cursor.execute(
            "UPDATE User SET nama_lengkap = %s, nomor_telepon = %s, email = %s, password = %s , role = %s WHERE user_id = %s",
            (data['nama_lengkap'], data['nomor_telepon'], data['email'], data['password'], data['role'], user_id)
        )
        db.commit()
        return jsonify({'message': 'User updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM User WHERE user_id = %s", (user_id,))
        db.commit()
        return jsonify({'message': 'User deleted successfully'})

@app.route('/rooms', methods=['GET', 'POST'])
def manage_rooms():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Kamar")
        rooms = cursor.fetchall()
        return jsonify(rooms)
    elif request.method == 'POST':
        data = request.get_json()
        cursor.execute(
            "INSERT INTO Kamar (tipe_kamar, harga, status_ketersediaan, jumlah_tamu, gambar) VALUES (%s, %i, %s, %i, %s)",
            (data['tipe_kamar'], data['harga'], data['status_ketersediaan'], data['jumlah_tamu'], data['gambar'])
        )
        db.commit()
        return jsonify({'message': 'Room created successfully'}), 201

@app.route('/rooms/<int:nomor_kamar>', methods=['GET', 'PUT', 'DELETE'])
def manage_room(nomor_kamar):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Kamar WHERE nomor_kamar = %s", (nomor_kamar,))
        room = cursor.fetchone()
        if room:
            return jsonify(room)
        else:
            return jsonify({'message': 'Room not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        cursor.execute(
            "UPDATE Kamar SET tipe_kamar = %s, harga = %s, status_ketersediaan = %s, jumlah_tamu = %s, gambar = %s WHERE nomor_kamar = %s",
            (data['tipe_kamar'], data['harga'], data['status_ketersediaan'], data['jumlah_tamu'], data['gambar'], nomor_kamar)
        )
        db.commit()
        return jsonify({'message': 'Room updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM Kamar WHERE nomor_kamar = %s", (nomor_kamar,))
        db.commit()
        return jsonify({'message': 'Room deleted successfully'})

@app.route('/bookings', methods=['GET', 'POST'])
def manage_bookings():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Pemesanan")
        bookings = cursor.fetchall()
        return jsonify(bookings)
    elif request.method == 'POST':
        data = request.get_json()
        cursor.execute(
            "INSERT INTO Pemesanan (user_id, nomor_kamar, tanggal_checkin, tanggal_checkout, jumlah_tamu, status_pembayaran) VALUES (%i, %i, %s, %s, %i, %s)",
            (data['user_id'], data['nomor_kamar'], data['tanggal_checkin'], data['tanggal_checkout'], data['jumlah_tamu'], data['status_pembayaran'])
        )
        db.commit()
        return jsonify({'message': 'Booking created successfully'}), 201

@app.route('/bookings/<int:nomor_pemesanan>', methods=['GET', 'PUT', 'DELETE'])
def manage_booking(nomor_pemesanan):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Pemesanan WHERE nomor_pemesanan = %s", (nomor_pemesanan,))
        booking = cursor.fetchone()
        if booking:
            return jsonify(booking)
        else:
            return jsonify({'message': 'Booking not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        cursor.execute(
            "UPDATE Pemesanan SET user_id = %s, nomor_kamar = %s, tanggal_checkin = %s, tanggal_checkout = %s, jumlah_tamu = %s, status_pembayaran = %s WHERE nomor_pemesanan = %s",
            (data['user_id'], data['nomor_kamar'], data['tanggal_checkin'], data['tanggal_checkout'], data['jumlah_tamu'], data['status_pembayaran'], nomor_pemesanan)
        )
        db.commit()
        return jsonify({'message': 'Booking updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM Pemesanan WHERE nomor_pemesanan = %s", (nomor_pemesanan,))
        db.commit()
        return jsonify({'message': 'Booking deleted successfully'})

@app.route('/facilities', methods=['GET', 'POST'])
def manage_facilities():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Fasilitas")
        facilities = cursor.fetchall()
        return jsonify(facilities)
    elif request.method == 'POST':
        data = request.get_json()
        cursor.execute(
            "INSERT INTO Fasilitas (nama_fasilitas, deskripsi, jam_operasional, gambar_fasilitas) VALUES (%s, %s, %s, %s)",
            (data['nama_fasilitas'], data['deskripsi'], data['jam_operasional'], data['gambar_fasilitas'])
        )
        db.commit()
        return jsonify({'message': 'Facility created successfully'}), 201

@app.route('/facilities/<int:id_fasilitas>', methods=['GET', 'PUT', 'DELETE'])
def manage_facility(id_fasilitas):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Fasilitas WHERE id_fasilitas = %s", (id_fasilitas,))
        facility = cursor.fetchone()
        if facility:
            return jsonify(facility)
        else:
            return jsonify({'message': 'Facility not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        cursor.execute(
            "UPDATE Fasilitas SET nama_fasilitas = %s, deskripsi = %s, jam_operasional = %s, gambar_fasilitas = %s WHERE id_fasilitas = %s",
            (data['nama_fasilitas'], data['deskripsi'], data['jam_operasional'], data['gambar_fasilitas'], id_fasilitas)
        )
        db.commit()
        return jsonify({'message': 'Facility updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM Fasilitas WHERE id_fasilitas = %s", (id_fasilitas,))
        db.commit()
        return jsonify({'message': 'Facility deleted successfully'})

@app.route('/reviews', methods=['GET', 'POST'])
def manage_reviews():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Review")
        reviews = cursor.fetchall()
        return jsonify(reviews)
    elif request.method == 'POST':
        data = request.get_json()
        cursor.execute(
            "INSERT INTO Review (user_id, email, komentar, timestamp) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)",
            (data['user_id'], data['email'], data['komentar'])
        )
        db.commit()
        return jsonify({'message': 'Review created successfully'}), 201

@app.route('/reviews/<int:id_komentar>', methods=['GET', 'PUT', 'DELETE'])
def manage_review(id_komentar):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Review WHERE id_komentar = %s", (id_komentar,))
        review = cursor.fetchone()
        if review:
            return jsonify(review)
        else:
            return jsonify({'message': 'Review not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        cursor.execute(
            "UPDATE Review SET user_id = %s, email = %s, komentar = %s, timestamp = CURRENT_TIMESTAMP WHERE id_komentar = %s",
            (data['user_id'], data['email'], data['komentar'], id_komentar)
        )
        db.commit()
        return jsonify({'message': 'Review updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM Review WHERE id_komentar = %s", (id_komentar,))
        db.commit()
        return jsonify({'message': 'Review deleted successfully'})

# Rute login
# Example snippet to log role data
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT user_id, nama_lengkap, password, role FROM User WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
        token = create_access_token(identity=user[0])
        return jsonify(access_token=token, role=user[3], username=user[1]), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401



# Contoh rute yang memerlukan autentikasi
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200
        
if __name__ == '__main__':
    app.run(debug=True)
