# MYAES

**MYAES** is a Python library that provides AES CTR encryption and decryption functionalities using the PyCryptodome library.

---

## Compilation and Installation

### Prerequisites

Before installing `MYAES`, ensure that you have the following:

- **Python 3.8** or higher
- **uv** (Astral's Python package manager) installed

To install `uv`, you can follow the instructions from the [official uv documentation](https://docs.astral.sh/uv/).

### Development Envitonment Setup

1. **Clone the repository**:
    ```bash
    git clone <repository-url>
    cd myaes
    ```

2. **Install dependencies and set up the environment**:
    ```bash
    uv sync
    ```

3. **Activate the virtual environment**:
    ```bash
    # On Linux/macOS
    source .venv/bin/activate

    # On Windows
    .venv\Scripts\activate
    ```

### Installation Steps

1. **Build the package**
    ```bash
    uv build
    ```

    After building, you can find the package wheel in the `dist/` folder, for example:

    ```
    dist/myaes-<version>-py3-none-any.whl
    ```

2. **Install the built package**
    ```bash
    pip install dist/myaes-<version>-py3-none-any.whl
    ```


## Running the Tests

`MYAES` uses `pytest` for testing. To run the tests:

1. **Ensure the virtual environment is active** (see activation above).

2. **Run the tests using `pytest`**:

    uv run pytest

This command will execute all test functions defined in the project.

### Interpreting Test Results

- **PASS**: The function behaves as expected.
- **FAIL**: Indicates that the function did not behave as expected. `pytest` will provide details on the failure, including the assertion that failed and the expected vs actual values.

## Example Usage

Here's a simple example demonstrating how to use the `MYAES` class:

```python
myaes = MYAES()
key = myaes.keygen()
msg = b"Transfer 100 DKK to Starbucks LT"

enc = myaes.encrypt(msg, key)
dec = myaes.decrypt(enc, key)

assert msg == dec
```

---

## Notes

- Ensure that your Python version is 3.8 or higher to avoid compatibility issues.
- The `uv sync` command simplifies the setup process by handling environment creation and dependency installation in one step.
- For any issues or contributions, please refer to the project's issue tracker or contact the maintainers.

---