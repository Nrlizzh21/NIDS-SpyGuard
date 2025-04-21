
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
)

;


CREATE TABLE prediction (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	upload_id INTEGER, 
	row_number INTEGER NOT NULL, 
	duration FLOAT, 
	protocol_type INTEGER, 
	service INTEGER, 
	src_bytes INTEGER, 
	dst_bytes INTEGER, 
	prediction VARCHAR(50) NOT NULL, 
	confidence FLOAT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	FOREIGN KEY(upload_id) REFERENCES upload (id)
)

;


CREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	password VARCHAR(120) NOT NULL, 
	email VARCHAR(120), 
	PRIMARY KEY (id), 
	CONSTRAINT uq_user_email UNIQUE (email), 
	UNIQUE (username)
)

;


CREATE TABLE upload (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	filename VARCHAR(255) NOT NULL, 
	upload_time DATETIME, 
	processing_time FLOAT, 
	dos_count INTEGER, 
	normal_count INTEGER, 
	probe_count INTEGER, 
	r2l_count INTEGER, 
	u2r_count INTEGER, 
	unknown_count INTEGER, 
	total_predictions INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
)

;

