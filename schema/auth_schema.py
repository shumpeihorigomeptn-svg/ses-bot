from pydantic import BaseModel, Field
class LoginRequest(BaseModel):
    username: str = Field(..., description="ユーザー名")
    password: str = Field(..., description="パスワード")


class LoginResponse(BaseModel):
    token: str = Field(..., description="認証トークン")
    token_type: str = Field(..., description="トークンタイプ")
    user_id: str = Field(..., description="ユーザーID")
    user_name: str = Field(..., description="ユーザー名")
