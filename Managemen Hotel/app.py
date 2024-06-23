from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from db import get_db, init_app
from flask_cors import CORS
import bcrypt
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)
init_app(app)

app.config['JWT_SECRET_KEY'] = 'secret'  # Replace with a strong secret key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}
jwt = JWTManager(app)

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Fungsi untuk menghasilkan nama file yang unik dengan prefix
def generate_unique_filename(prefix, filename):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    extension = filename.split('.')[-1]
    new_filename = f"{prefix}_{timestamp}.{extension}"
    return new_filename

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
        cursor.execute("SELECT id_kamar, nomor_kamar, tipe_kamar, harga, status_ketersediaan, jumlah_tamu, gambar FROM Kamar")
        rooms = cursor.fetchall()
        rooms_list = []
        for room in rooms:
            rooms_list.append({
                'id_kamar': room[0],  # Pastikan ini ada
                'nomor_kamar': room[1],
                'tipe_kamar': room[2],
                'harga': room[3],
                'status_ketersediaan': room[4],
                'jumlah_tamu': room[5],
                'gambar': room[6]
            })
        return jsonify(rooms_list)
    elif request.method == 'POST':
        data = request.form
        file = request.files['image']
        filename = generate_unique_filename('room', file.filename)  # Menggunakan fungsi generate_unique_filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        cursor.execute(
            "INSERT INTO Kamar (nomor_kamar, tipe_kamar, harga, status_ketersediaan, jumlah_tamu, gambar) VALUES (%s, %s, %s, %s, %s, %s)",
            (data['roomNumber'], data['roomType'], data['price'], data['availability'], data['maxPerson'], filename)
        )
        db.commit()
        return jsonify({'message': 'Room created successfully'}), 201

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/rooms/<int:id_kamar>', methods=['GET', 'PUT', 'DELETE'])
def manage_room(id_kamar):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Kamar WHERE id_kamar = %s", (id_kamar,))
        room = cursor.fetchone()
        if room:
            return jsonify(room)
        else:
            return jsonify({'message': 'Room not found'}), 404
    elif request.method == 'PUT':
        data = request.form
        file = request.files.get('image')
        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            filename = data['gambar']  # Use existing filename if no new image

        cursor.execute(
            "UPDATE Kamar SET nomor_kamar = %s, tipe_kamar = %s, harga = %s, status_ketersediaan = %s, jumlah_tamu = %s, gambar = %s WHERE id_kamar = %s",
            (data['roomNumber'], data['roomType'], data['price'], data['availability'], data['maxPerson'], filename, id_kamar)
        )
        db.commit()
        return jsonify({'message': 'Room updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM Kamar WHERE id_kamar = %s", (id_kamar,))
        db.commit()
        return jsonify({'message': 'Room deleted successfully'})

@app.route('/bookings', methods=['GET', 'POST'])
def manage_bookings():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM pemesanan")
        bookings = cursor.fetchall()
        bookings_list = []
        for booking in bookings:
            bookings_list.append({
                'id': booking[0],
                'roomNumber': booking[4],
                'checkIn': booking[5],
                'checkOut': booking[6],
                'guests': booking[3],
                'paymentStatus': booking[7]
            })
        return jsonify(bookings_list)
    elif request.method == 'POST':
        @jwt_required()
        def post_booking():
            try:
                user_id = get_jwt_identity()
                id_kamar = request.form.get('id_kamar')
                tanggal_checkin = request.form.get('tanggal_checkin')
                tanggal_checkout = request.form.get('tanggal_checkout')
                bukti_pembayaran = request.files['bukti_pembayaran']

                # Log data yang diterima
                print(f"User ID: {user_id}, ID Kamar: {id_kamar}, Tanggal Check-in: {tanggal_checkin}, Tanggal Check-out: {tanggal_checkout}")

                # Mendapatkan nama lengkap dari User
                cursor.execute("SELECT nama_lengkap FROM User WHERE user_id = %s", (user_id,))
                result = cursor.fetchone()
                if result:
                    nama_lengkap = result[0]
                else:
                    return jsonify({'error': 'User not found'}), 404

                # Mendapatkan data kamar dari tabel Kamar
                cursor.execute("SELECT nomor_kamar FROM Kamar WHERE id_kamar = %s", (id_kamar,))
                result = cursor.fetchone()
                if result:
                    nomor_kamar = result
                else:
                    return jsonify({'error': 'Room not found'}), 404

                # Validasi file
                if not bukti_pembayaran or not allowed_file(bukti_pembayaran.filename):
                    return jsonify({"message": "Invalid file"}), 400
                
                filename = secure_filename(bukti_pembayaran.filename)
                bukti_pembayaran.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Debugging: Print all values before executing the query
                print(f"Values: {user_id}, {id_kamar}, {nama_lengkap}, {nomor_kamar}, {tanggal_checkin}, {tanggal_checkout}, {filename}")

                cursor.execute(
                    'INSERT INTO pemesanan (user_id, id_kamar, nama_lengkap, nomor_kamar, tanggal_checkin, tanggal_checkout, bukti_pembayaran) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                    (user_id, id_kamar, nama_lengkap, nomor_kamar, tanggal_checkin, tanggal_checkout, filename)
                )
                db.commit()

                # Ambil data pemesanan yang baru saja dimasukkan
                cursor.execute("SELECT * FROM pemesanan WHERE user_id = %s ORDER BY nomor_pemesanan DESC LIMIT 1", (user_id,))
                new_booking = cursor.fetchone()
                booking_data = {
                    'id': new_booking[0],
                    'roomNumber': new_booking[4],
                    'checkIn': new_booking[5],
                    'checkOut': new_booking[6],
                    'guests': new_booking[3]
                }
                
                return jsonify(booking_data), 201
            except Exception as e:
                print(f"Error: {e}")
                return jsonify({"message": "Booking failed"}), 500

        return post_booking()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
            "UPDATE pemesanan SET user_id = %s, nomor_kamar = %s, tanggal_checkin = %s, tanggal_checkout = %s, jumlah_tamu = %s WHERE nomor_pemesanan = %s",
            (data['user_id'], data['nomor_kamar'], data['tanggal_checkin'], data['tanggal_checkout'], data['jumlah_tamu'], nomor_pemesanan)
        )
        db.commit()
        return jsonify({'message': 'Booking updated successfully'})
    elif request.method == 'DELETE':
        cursor.execute("DELETE FROM pemesanan WHERE nomor_pemesanan = %s", (nomor_pemesanan,))
        db.commit()
        return jsonify({'message': 'Booking deleted successfully'})

@app.route('/facilities', methods=['GET', 'POST'])
def manage_facilities():
    db = get_db()
    cursor = db.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT * FROM Fasilitas")
        facilities = cursor.fetchall()
        facilities_list = []
        for facility in facilities:
            facilities_list.append({
                'id_fasilitas': facility[0],
                'nama_fasilitas': facility[1],
                'gambar_fasilitas': facility[2],
                'deskripsi': facility[3]
            })
        return jsonify(facilities_list)
    elif request.method == 'POST':
        nama_fasilitas = request.form['name']
        file = request.files['image']
        deskripsi = request.form['description']

        # Secure filename
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        cursor.execute(
            "INSERT INTO Fasilitas (nama_fasilitas, deskripsi, gambar_fasilitas) VALUES (%s, %s, %s)",
            (nama_fasilitas, deskripsi, filename)
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
            "UPDATE Fasilitas SET nama_fasilitas = %s, deskripsi = %s, gambar_fasilitas = %s WHERE id_fasilitas = %s",
            (data['nama_fasilitas'], data['deskripsi'], data['gambar_fasilitas'], id_fasilitas)
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
        cursor.execute("SELECT id_komentar, email, komentar, tanggal_komentar FROM review")
        reviews = cursor.fetchall()
        reviews_list = []
        for review in reviews:
            reviews_list.append({
                'id_komentar': review[0],
                'email': review[1],
                'komentar': review[2],
                'tanggal_komentar': review[3].strftime('%Y-%m-%d')  # Formatting tanggal_komentar
            })
        return jsonify(reviews_list)
    elif request.method == 'POST':
        data = request.get_json()
        cursor.execute(
            "INSERT INTO Review (email, komentar, tanggal_komentar) VALUES (%s, %s, NOW())",
            (data['email'], data['komentar'])
        )
        db.commit()
        return jsonify({'message': 'Review created successfully'}), 201


@app.route('/reviews/<int:id_komentar>', methods=['DELETE'])
def delete_review(id_komentar):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM Review WHERE id_komentar = %s", (id_komentar,))
    db.commit()
    return jsonify({'message': 'Review deleted successfully'})

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

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify(logged_in_as=current_user_id), 200

if __name__ == '__main__':
    app.run(debug=True)
