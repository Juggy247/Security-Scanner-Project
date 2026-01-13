"""
Strategic Text Extraction and Preprocessing for Security Scanner
Extracts and normalizes website text for SBERT embedding generation.
"""

from bs4 import BeautifulSoup
from typing import Dict, Any, Optional
import re
from urllib.parse import urlparse


class TextProcessor:
    """
    Extracts and processes text from HTML for semantic analysis.
    
    Uses strategic extraction with weighting:
    - Title: 3x weight (most important)
    - Meta description: 2x weight
    - H1 headings: 2x weight
    - Form text: 2x weight (phishing indicators)
    - Body preview: 1x weight (first 500 chars)
    """
    
    # Text extraction weights
    WEIGHTS = {
        'title': 3,
        'description': 2,
        'headings': 2,
        'form_text': 2,
        'body': 1
    }
    
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Clean and normalize text.
        
        Steps:
        1. Remove extra whitespace
        2. Remove special characters (keep punctuation)
        3. Lowercase
        4. Strip
        
        Args:
            text: Raw text to clean
        
        Returns:
            Cleaned text
        """
        if not text:
            return ""
        
        # Remove extra whitespace (multiple spaces, newlines, tabs)
        text = re.sub(r'\s+', ' ', text)
        
        # Remove non-printable characters but keep basic punctuation
        text = re.sub(r'[^\w\s\.\,\!\?\-\:\;\'\"]', '', text)
        
        # Lowercase
        text = text.lower()
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text
    
    @staticmethod
    def extract_title(soup: BeautifulSoup) -> str:
        """
        Extract and clean page title.
        
        Args:
            soup: BeautifulSoup object
        
        Returns:
            Cleaned title text
        """
        title_tag = soup.find('title')
        
        if title_tag and title_tag.string:
            title = title_tag.string.strip()
            return TextProcessor.clean_text(title)
        
        return ""
    
    @staticmethod
    def extract_meta_description(soup: BeautifulSoup) -> str:
        """
        Extract meta description.
        
        Args:
            soup: BeautifulSoup object
        
        Returns:
            Cleaned meta description
        """
        # Try different meta description variations
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc:
            meta_desc = soup.find('meta', attrs={'property': 'og:description'})
        
        if meta_desc and meta_desc.get('content'):
            description = meta_desc.get('content')
            return TextProcessor.clean_text(description)
        
        return ""
    
    @staticmethod
    def extract_headings(soup: BeautifulSoup) -> str:
        """
        Extract H1 headings (most important headings).
        
        Args:
            soup: BeautifulSoup object
        
        Returns:
            Combined cleaned heading text
        """
        h1_tags = soup.find_all('h1')
        
        headings = []
        for h1 in h1_tags[:5]:  # Limit to first 5 h1 tags
            text = h1.get_text()
            if text:
                headings.append(TextProcessor.clean_text(text))
        
        return '. '.join(headings) if headings else ""
    
    @staticmethod
    def extract_body_preview(soup: BeautifulSoup, max_chars: int = 500) -> str:
        """
        Extract preview of body text (first N characters).
        
        Args:
            soup: BeautifulSoup object
            max_chars: Maximum characters to extract
        
        Returns:
            Cleaned body preview
        """
        # Remove script and style elements
        for script in soup(["script", "style", "noscript", "iframe"]):
            script.decompose()
        
        # Get body tag
        body = soup.find('body')
        
        if body:
            # Get text from body
            body_text = body.get_text()
            
            # Clean and limit
            cleaned = TextProcessor.clean_text(body_text)
            
            # Take first max_chars
            preview = cleaned[:max_chars]
            
            return preview
        
        return ""
    
    @staticmethod
    def extract_form_text(soup: BeautifulSoup) -> str:
        """
        Extract text from forms (important for phishing detection).
        
        Phishing sites often have forms with suspicious text like:
        - "Enter your password"
        - "Credit card number"
        - "Verify your account"
        
        Args:
            soup: BeautifulSoup object
        
        Returns:
            Combined form-related text
        """
        forms = soup.find_all('form')
        
        form_texts = []
        
        for form in forms[:3]:  # Limit to first 3 forms
            # Get all text within the form
            form_text = form.get_text()
            
            # Get placeholder text from inputs
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                placeholder = input_field.get('placeholder', '')
                if placeholder:
                    form_text += f" {placeholder}"
                
                # Get label text
                field_id = input_field.get('id') or input_field.get('name')
                if field_id:
                    label = form.find('label', attrs={'for': field_id})
                    if label:
                        form_text += f" {label.get_text()}"
            
            if form_text:
                form_texts.append(TextProcessor.clean_text(form_text))
        
        return '. '.join(form_texts) if form_texts else ""
    
    @staticmethod
    def combine_with_weights(parts: Dict[str, str]) -> str:
        """
        Combine text parts with weights.
        
        Parts with higher weights are repeated more times to give them
        more importance in the final embedding.
        
        Args:
            parts: Dictionary of text parts (title, description, etc.)
        
        Returns:
            Combined weighted text
        """
        combined = []
        
        # Add each part according to its weight
        for part_name, weight in TextProcessor.WEIGHTS.items():
            text = parts.get(part_name, '')
            if text:
                # Repeat text according to weight
                for _ in range(weight):
                    combined.append(text)
        
        # Join with periods for sentence separation
        return '. '.join(combined)
    
    @staticmethod
    def extract_from_html(html_content: str, url: str) -> Dict[str, Any]:
        """
        Main extraction method - extracts all text features from HTML.
        
        Args:
            html_content: Raw HTML content
            url: The URL being processed (for metadata)
        
        Returns:
            Dictionary with extracted and processed text
        """
        try:
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract individual parts
            title = TextProcessor.extract_title(soup)
            description = TextProcessor.extract_meta_description(soup)
            headings = TextProcessor.extract_headings(soup)
            body_preview = TextProcessor.extract_body_preview(soup, max_chars=500)
            form_text = TextProcessor.extract_form_text(soup)
            
            # Combine parts
            parts = {
                'title': title,
                'description': description,
                'headings': headings,
                'body': body_preview,
                'form_text': form_text
            }
            
            # Create weighted combination
            combined_text = TextProcessor.combine_with_weights(parts)
            
            # Calculate lengths
            total_length = len(combined_text)
            
            return {
                'success': True,
                'url': url,
                'extraction_date': None,  # Will be set by database
                
                # Individual parts
                'title': title,
                'title_length': len(title),
                
                'description': description,
                'description_length': len(description),
                
                'headings': headings,
                'headings_length': len(headings),
                
                'body_preview': body_preview,
                'body_length': len(body_preview),
                
                'form_text': form_text,
                'form_text_length': len(form_text),
                
                # Combined result (this is what gets embedded)
                'combined_text': combined_text,
                'combined_length': total_length,
                
                # Metadata
                'weights_applied': True,
                'preprocessing': {
                    'lowercase': True,
                    'removed_html': True,
                    'removed_special_chars': True,
                    'normalized_whitespace': True
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'url': url,
                'error': str(e),
                'combined_text': ''
            }
    
    @staticmethod
    def extract_from_response(response, url: str) -> Dict[str, Any]:
        """
        Extract text from HTTP response object.
        
        Args:
            response: requests.Response object
            url: The URL
        
        Returns:
            Extracted text data
        """
        try:
            # Decode content
            html_content = response.content.decode('utf-8', errors='ignore')
            
            # Extract text
            return TextProcessor.extract_from_html(html_content, url)
            
        except Exception as e:
            return {
                'success': False,
                'url': url,
                'error': f"Failed to decode response: {str(e)}",
                'combined_text': ''
            }
    
    @staticmethod
    def validate_text_data(text_data: Dict[str, Any], min_length: int = 20) -> bool:
        """
        Validate that extracted text is usable.
        
        Args:
            text_data: Extracted text data
            min_length: Minimum required length for combined text
        
        Returns:
            True if text is valid for embedding
        """
        if not text_data.get('success'):
            return False
        
        combined = text_data.get('combined_text', '')
        
        # Must have minimum length
        if len(combined) < min_length:
            return False
        
        # Must have at least title or description
        if not text_data.get('title') and not text_data.get('description'):
            return False
        
        return True


# Testing and examples
if __name__ == "__main__":
    # Example 1: Extract from HTML string
    sample_html = """
    <html>
        <head>
            <title>Verify Your PayPal Account Now!</title>
            <meta name="description" content="Your account will be locked. Click here immediately.">
        </head>
        <body>
            <h1>Urgent Account Verification Required</h1>
            <p>Your PayPal account has been limited due to suspicious activity.</p>
            <form>
                <input type="text" placeholder="Enter your password">
                <input type="text" placeholder="Credit card number">
                <button>Verify Now</button>
            </form>
        </body>
    </html>
    """
    
    processor = TextProcessor()
    result = processor.extract_from_html(sample_html, "http://fake-paypal.tk")
    
    print("="*60)
    print("📝 TEXT EXTRACTION EXAMPLE")
    print("="*60)
    print(f"\nURL: {result['url']}")
    print(f"Success: {result['success']}")
    print(f"\n--- Individual Parts ---")
    print(f"Title: {result['title']}")
    print(f"Description: {result['description']}")
    print(f"Headings: {result['headings']}")
    print(f"Form text: {result['form_text']}")
    print(f"Body preview: {result['body_preview'][:100]}...")
    
    print(f"\n--- Combined Text (for embedding) ---")
    print(f"Length: {result['combined_length']} chars")
    print(f"Text: {result['combined_text'][:200]}...")
    
    print(f"\n--- Validation ---")
    is_valid = TextProcessor.validate_text_data(result)
    print(f"Valid for embedding: {is_valid}")
    
    print("\n" + "="*60)
    
    # Example 2: Legitimate site
    sample_html_safe = """
    <html>
        <head>
            <title>GitHub - Where the world builds software</title>
            <meta name="description" content="GitHub is where people build software.">
        </head>
        <body>
            <h1>Build and ship software on a single, collaborative platform</h1>
            <p>Join the world's most widely adopted AI-powered developer platform.</p>
        </body>
    </html>
    """
    
    result_safe = processor.extract_from_html(sample_html_safe, "https://github.com")
    
    print("\n📝 SAFE SITE EXAMPLE")
    print("="*60)
    print(f"Title: {result_safe['title']}")
    print(f"Combined: {result_safe['combined_text'][:150]}...")
    print("="*60)