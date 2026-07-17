import json
import logging

from skill_sheet_text import extract_skill_sheet_text_safe

from command.llm_wrapper.llm_wrapper import LLMAPI
from command.llm_wrapper.prompt import (
    make_case_supabase_messages,
    make_requirement_messages,
    make_proposal_messages,
    make_evaluate_score_messages,
    make_proposal_generation_messages
)
from database.supa_utils import (
    get_current_datetime_iso,
    get_supabase_case_count,
    get_supabase_client_id,
    insert_case_management_to_supabase,
    get_supabase_caseid_from_num,
    get_supabase_case_summary,
    insert_proposal_record,
    get_bp_id_by_slack_channel,
    get_proposal_count_by_case,
)
from schema.api_schema import (
    CaseSummaryRequest,
    CaseSummaryResponse,
    RequirementRequest,
    RequirementResponse,
    ProposalRequest,
    ProposalResponse,
)

logger = logging.getLogger(__name__)


def generate_requirement(request: RequirementRequest) -> RequirementResponse:
    """
    顧客要望の概要を作成するAI呼び出し関数

    Args:
        request (RequirementRequest): 要求生成リクエストデータ
    Returns:
        RequirementResponse: 要求生成レスポンスデータ
    """

    logger.info(f"Generating requirement for user_id: {request.user_id}, client_name: {request.client_name}")
    
    llm_api = LLMAPI()
    
    prompt = request.text
    messages = make_requirement_messages(prompt)
    try:
        response = llm_api.request_openai(messages)
    
    except Exception as e:
        logger.error(f"Error during LLM API request: {e}")
        return RequirementResponse(status="error", requirement_text="")

    return RequirementResponse(status="success", requirement_text=response)


def generate_case_supabase(request: CaseSummaryRequest) -> CaseSummaryResponse:
    """
    案件概要を作成するAI呼び出し関数

    Args:
        request (CaseSummaryRequest): 案件概要生成リクエストデータ
    Returns:
        CaseSummaryResponse: 案件概要生成レスポンスデータ
    """

    logger.info(f"Generating case summary for user_id: {request.user_id}, client_name: {request.client_name}")
    
    llm_api = LLMAPI()
    
    prompt = request.requirement_text
    messages = make_case_supabase_messages(prompt)
    try:
        response = llm_api.request_openai(messages)
        print(response)
        # responseから、jsonのみを抽出
        response = response.strip()
        start_index = response.find("{")
        end_index = response.rfind("}") + 1
        if start_index == -1 or end_index == -1:
            raise ValueError("Response does not contain valid JSON object")
        json_response = json.loads(response[start_index:end_index])
        # 必要なフィールドをjsonに挿入
        json_response["client_id"] = get_supabase_client_id(request.client_name)
        json_response["user_id"] = request.user_id
        json_response["user_name"] = request.user_name
        # case_managementの何番目のデータかを取得
        json_response["number"] = get_supabase_case_count()
        json_response["updated_date"] = get_current_datetime_iso()
        json_response["case_summary"] = request.requirement_text
        print(json_response) 
        # json_responseを、supabaseに登録する処理をここに追加
        status, case_id = insert_case_management_to_supabase(json_response)
        if not status:
            raise ValueError("Failed to insert case management to Supabase")

    
    except Exception as e:
        logger.error(f"Error during LLM API request: {e}")
        return CaseSummaryResponse(status="error", case_id="")

    return CaseSummaryResponse(status="success", case_id=case_id)


def generate_proposal_supabase(request: ProposalRequest) -> ProposalResponse:
    """
    bpからの提案をsupabaseデータを使用して生成するAI呼び出し関数

    Args:
        request (ProposalRequest): 提案生成リクエストデータ
    Returns:
        ProposalResponse: 提案生成レスポンスデータ
    """

    logger.info(f"Generating proposal for case_num: {request.case_num}, proposal_link: {request.proposal_link}")
    
    llm_api = LLMAPI()
    
    prompt = request.candidate_profiles
    if request.skill_sheet:
        logger.info(
            "Skill sheet受領: filename=%s content_type=%s",
            getattr(request.skill_sheet, "filename", "unknown"),
            getattr(request.skill_sheet, "content_type", "unknown"),
        )
    skill_text, skill_sheet_warning = extract_skill_sheet_text_safe(request.skill_sheet)
    if skill_text:
        prompt += "\n\nスキルシートの内容:\n" + skill_text
    messages = make_proposal_messages(prompt)
    try:
        response = llm_api.request_openai(messages)
        print(response)
        # responseから、jsonのみを抽出
        response = response.strip()
        start_index = response.find("{")
        end_index = response.rfind("}") + 1
        if start_index == -1 or end_index == -1:
            raise ValueError("Response does not contain valid JSON object")
        json_response = json.loads(response[start_index:end_index])
        # 必要なフィールドをjsonに挿入
        json_response["case_id"] = get_supabase_caseid_from_num(request.case_num)
        proposal_count = get_proposal_count_by_case(json_response["case_id"])
        json_response["proposal_code"] = f"ID_{request.case_num}_{proposal_count + 1}"
        case_summary = get_supabase_case_summary(json_response["case_id"])
        # 案件概要をもとに、評価スコアを算出
        score_messages = make_evaluate_score_messages(case_summary, prompt)
        score_response = llm_api.request_openai(score_messages)
        print(score_response)

        score_response = score_response.strip()
        start_index = score_response.find("{")  
        end_index = score_response.rfind("}") + 1
        if start_index == -1 or end_index == -1:
            raise ValueError("Score response does not contain valid JSON object")
        try:
            score_json = json.loads(score_response[start_index:end_index])
            json_response["score"] = score_json.get("score")
            json_response["evaluation"] = score_json.get("evaluation")
            if score_json.get("score") is not None and score_json.get("score") >= 80:
                json_response["proposal_status"] = True
            else:
                json_response["proposal_status"] = False
        except json.JSONDecodeError:
            logger.warning("Failed to decode score response JSON")
        
        json_response["bp_link"] = request.proposal_link
        # Slack permalinks contain cid=channelID. Extract and lookup BP.
        slack_channel_id = None
        if request.proposal_link and "cid=" in request.proposal_link:
            slack_channel_id = request.proposal_link.split("cid=")[-1].split("&")[0]
        if slack_channel_id:
            try:
                bp_id = get_bp_id_by_slack_channel(slack_channel_id)
            except Exception as exc:
                bp_id = None
                logger.error("Slackチャンネル %s からBP IDの取得に失敗しました: %s", slack_channel_id, exc)
            if bp_id:
                json_response["bp_id"] = bp_id
            else:
                logger.warning("Slackチャンネル %s に紐づくBPが見つかりません", slack_channel_id)
        proposal_generation_messages = make_proposal_generation_messages(case_summary, prompt)
        print("提案書作成してます。")
        proposal_response = llm_api.request_openai(proposal_generation_messages)
        json_response["proposal"] = proposal_response
        print(json_response) 
        # json_responseを、supabaseに登録する処理をここに追加
        response = insert_proposal_record(json_response)
        if not response:
            raise ValueError("Failed to insert case management to Supabase")

    
    except Exception as e:
        logger.error(f"Error during LLM API request: {e}")
        return ProposalResponse(status="error", proposal_id="", warning=skill_sheet_warning)

    return ProposalResponse(status="success", proposal_id=response.get("id", ""), warning=skill_sheet_warning)
