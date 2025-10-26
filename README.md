# DATA DRIVEN DEFENCE: MODERN APPROACHES TO PHISHING WEBSITES CLASSIFICATION

## Installation

To use this project, you will need to have the following installed:

- Python 3.x
- Flask
- NumPy
- Pickle

You can install the required dependencies using pip:

```
pip install flask numpy
```

## Usage

1. Clone the repository:

```
git clone https://github.com/varshith46/DATA-DRIVEN-DEFENSE-OF-PHISHING-WEBSITE.git
```

2. Navigate to the project directory:

```
cd data-driven-defence
```

3. Run the Flask app:

```
python app.py
```

4. Open your web browser and go to `http://localhost:5000` to access the application.

## API

The application provides the following API endpoint:

- `POST /result`: Accepts a URL as input and returns the prediction result (whether the website is safe or unsafe).

## Contributing

If you would like to contribute to this project, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Submit a pull request to the original repository.

## License

This project is licensed under the [MIT License](LICENSE).

## Testing

To run the tests for this project, you can use the following command:

```
python -m unittest discover tests
```

This will run all the test cases in the `tests` directory.
