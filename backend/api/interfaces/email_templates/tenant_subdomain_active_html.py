import html


def tenant_subdomain_active_html(subdomain_link: str) -> str:
    """HTML email template for tenant subdomain activation."""
    # Same href-attribute escaping as the live link templates (iteration
    # 989): this template has no live callers today, but its link was
    # the last unescaped href interpolation in the codebase, so a future
    # caller passing a quote-bearing value would otherwise break out of
    # the href attribute. Normal links render identically apart from
    # &amp;, which clients decode to &.
    subdomain_link = html.escape(subdomain_link or "", quote=True)
    return f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Your subdomain is ready!</h2>
            
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="{subdomain_link}" 
                style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
                    Visit Now
                </a>
            </div>
            
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #007bff;">{subdomain_link}</p>
        </div>
    """
